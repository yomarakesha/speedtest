// Package monitor turns the one-shot probes (ping, port scan, audit, bandwidth)
// into continuous checks that fire alerts when a threshold is breached or a
// tracked value drifts. It is built as a stateless core plus a thin loop:
//
//   - `monitor check` runs one pass of every configured check and exits non-zero
//     if anything is currently breaching — ideal for cron / CI.
//   - `monitor run` loops, firing each check on its own interval.
//
// Both share the same YAML config, probes and alert sinks. Each probe's
// threshold logic is a pure eval* function (unit-tested without the network);
// the probe wrapper only adds the live measurement around it.
package monitor

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// Severity ranks an alert. Kept as plain strings so config, JSON and stdout all
// read the same.
const (
	SevInfo = "info"
	SevWarn = "warn"
	SevCrit = "crit"
)

// Alert is a single threshold breach or drift event produced by a probe.
type Alert struct {
	Time     time.Time `json:"time"`
	Check    string    `json:"check"`  // probe type, e.g. "ping"
	Target   string    `json:"target"` // host or interface the alert is about
	Severity string    `json:"severity"`
	Title    string    `json:"title"`  // short summary
	Detail   string    `json:"detail"` // what/why
}

// String renders an alert as a single stdout log line.
func (a Alert) String() string {
	ts := a.Time.Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s  [%s] %s/%s: %s", ts, a.Severity, a.Check, a.Target, a.Title)
	if a.Detail != "" {
		line += " — " + a.Detail
	}
	return line
}

// Result is the outcome of one probe pass.
type Result struct {
	Check  string
	Target string
	Err    error   // probe failed to measure (not a breach); logged, never fatal
	Alerts []Alert // threshold breaches / drift events
}

// Probe is one configured check. Interval is used by `monitor run`; `monitor
// check` ignores it and runs every probe once.
type Probe interface {
	Name() string
	Target() string
	Interval() time.Duration
	Run(ctx context.Context) Result
}

// Sink delivers an alert to one destination (stdout, webhook, desktop, history).
type Sink interface {
	Name() string
	Deliver(a Alert) error
}

// Dispatcher fans one alert out to every enabled sink. A sink failure is logged
// to stderr and never blocks the other sinks or stops monitoring. Deliver is
// safe for concurrent use: `Run` fires probes in parallel and they share one
// dispatcher, so delivery is serialized to keep sink output from interleaving.
type Dispatcher struct {
	mu    sync.Mutex
	sinks []Sink
}

// NewDispatcher builds a dispatcher over the given sinks.
func NewDispatcher(sinks ...Sink) *Dispatcher { return &Dispatcher{sinks: sinks} }

// Deliver sends a to every sink, collecting (but not propagating) errors.
func (d *Dispatcher) Deliver(a Alert) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.sinks {
		if err := s.Deliver(a); err != nil {
			fmt.Fprintf(os.Stderr, "monitor: sink %s: %v\n", s.Name(), err)
		}
	}
}

// Check runs every probe once, delivers all alerts, and reports whether any
// probe is currently breaching. It is the stateless core shared by the CLI
// `check` subcommand and each tick of `run`.
func Check(ctx context.Context, probes []Probe, d *Dispatcher) (breached bool) {
	for _, p := range probes {
		res := p.Run(ctx)
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "monitor: %s/%s: %v\n", res.Check, res.Target, res.Err)
		}
		for _, a := range res.Alerts {
			breached = true
			d.Deliver(a)
		}
	}
	return breached
}

// Run loops until ctx is cancelled, firing each probe on its own interval. Every
// probe runs once immediately at start so problems surface without waiting a
// full interval.
func Run(ctx context.Context, probes []Probe, d *Dispatcher) {
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(p Probe) {
			defer wg.Done()
			runProbeLoop(ctx, p, d)
		}(p)
	}
	wg.Wait()
}

// runProbeLoop runs one probe immediately, then on every interval tick.
func runProbeLoop(ctx context.Context, p Probe, d *Dispatcher) {
	fire := func() {
		res := p.Run(ctx)
		if res.Err != nil {
			fmt.Fprintf(os.Stderr, "monitor: %s/%s: %v\n", res.Check, res.Target, res.Err)
		}
		for _, a := range res.Alerts {
			d.Deliver(a)
		}
	}
	fire()
	iv := p.Interval()
	if iv <= 0 {
		iv = time.Minute
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fire()
		}
	}
}

// sortInts returns a sorted copy so callers can diff / persist a stable order.
func sortInts(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}
