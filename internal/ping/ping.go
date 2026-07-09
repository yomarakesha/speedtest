// Package ping measures TCP-connect round-trip latency to any host:port.
// Unlike the LAN throughput test, this needs nothing running on the target —
// it works against any device that has at least one open/closed-but-reachable
// TCP port (router, phone, printer, server, ...).
//
// The measurement is exposed as a streaming engine (Probe) that emits one
// Sample per attempt; both the headless CLI renderer (RunPing) and the TUI
// consume the same stream so their numbers can never drift apart.
package ping

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sort"
	"time"

	"speedtest/internal/util"
)

// Result is the summary of a ping run (used for --json output).
type Result struct {
	Host     string  `json:"host"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	MinMs    float64 `json:"min_ms"`
	AvgMs    float64 `json:"avg_ms"`
	MaxMs    float64 `json:"max_ms"`
}

// Options configures a ping run.
type Options struct {
	Host     string        // host or host:port; DefaultPort fills a missing port
	Count    int           // attempts; <= 0 means run until the context is canceled
	Timeout  time.Duration // per-attempt dial timeout
	Interval time.Duration // delay between attempts
}

// Sample is the outcome of a single probe. Err is set when the dial failed.
type Sample struct {
	Seq   int
	RTTMs float64
	Err   error
}

// OK reports whether the probe connected.
func (s Sample) OK() bool { return s.Err == nil }

// DefaultPort is probed when the host has no explicit :port.
const DefaultPort = 80

// NormalizeHost returns host:port, defaulting the port when absent.
func NormalizeHost(host string, port int) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, fmt.Sprint(port))
	}
	return host
}

// Probe runs the ping loop and sends one Sample per attempt on the returned
// channel, closing it when Count is reached or the context is canceled. Host in
// opt must already be host:port (see NormalizeHost).
func Probe(ctx context.Context, opt Options) <-chan Sample {
	out := make(chan Sample)
	go func() {
		defer close(out)
		for i := 0; opt.Count <= 0 || i < opt.Count; i++ {
			dctx, cancel := context.WithTimeout(ctx, opt.Timeout)
			t0 := time.Now()
			conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", opt.Host)
			rtt := time.Since(t0).Seconds() * 1000
			cancel()
			s := Sample{Seq: i + 1}
			if err != nil {
				s.Err = err
			} else {
				conn.Close()
				s.RTTMs = rtt
			}
			select {
			case out <- s:
			case <-ctx.Done():
				return
			}
			last := opt.Count > 0 && i == opt.Count-1
			if !last {
				select {
				case <-time.After(opt.Interval):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// Summarize folds a set of samples into a Result.
func Summarize(host string, sent int, samples []Sample) Result {
	res := Result{Host: host, Sent: sent}
	var rtts []float64
	for _, s := range samples {
		if s.OK() {
			rtts = append(rtts, s.RTTMs)
		}
	}
	res.Received = len(rtts)
	if sent > 0 {
		res.LossPct = float64(sent-len(rtts)) / float64(sent) * 100
	}
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		sum := 0.0
		for _, r := range rtts {
			sum += r
		}
		res.MinMs = rtts[0]
		res.MaxMs = rtts[len(rtts)-1]
		res.AvgMs = sum / float64(len(rtts))
	}
	return res
}

// RunPing is the CLI entry point for `speedtest ping <host>`.
func RunPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	count := fs.Int("count", 5, "number of attempts")
	port := fs.Int("port", DefaultPort, "TCP port to probe (if host has no :port)")
	timeout := fs.Duration("timeout", 2*time.Second, "per-attempt timeout")
	interval := fs.Duration("interval", 500*time.Millisecond, "delay between attempts")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest ping <host[:port]> [--count N] [--port P]")
	}

	host := NormalizeHost(pos[0], *port)

	if !*asJSON {
		fmt.Printf("ПИНГ (TCP) %s  -  попыток: %d\n", host, *count)
	}

	opt := Options{Host: host, Count: *count, Timeout: *timeout, Interval: *interval}
	var samples []Sample
	for s := range Probe(context.Background(), opt) {
		samples = append(samples, s)
		if *asJSON {
			continue
		}
		if s.OK() {
			fmt.Printf("  #%d: %.2f мс\n", s.Seq, s.RTTMs)
		} else {
			fmt.Printf("  #%d: ошибка (%v)\n", s.Seq, cleanErr(s.Err))
		}
	}

	res := Summarize(host, *count, samples)

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Println()
	if res.Received == 0 {
		fmt.Printf("%s недоступен на этом порту (потери 100%%).\n", host)
		fmt.Println("Попробуйте другой --port (напр. 443, 22, 445) — устройство")
		fmt.Println("отвечает только на портах, которые у него реально открыты.")
		return nil
	}
	fmt.Printf("мин %.2f / сред %.2f / макс %.2f мс   потери %.0f%% (%d/%d)\n",
		res.MinMs, res.AvgMs, res.MaxMs, res.LossPct, res.Received, res.Sent)
	return nil
}

// cleanErr trims a dial error to its most useful part.
func cleanErr(err error) string {
	if oe, ok := err.(*net.OpError); ok && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}
