package monitor

import (
	"context"
	"fmt"
	"time"

	"speedtest/internal/ping"
)

// pingProbe measures TCP-connect latency/loss to a target and alerts when the
// average RTT or loss percentage exceeds the configured thresholds.
type pingProbe struct {
	spec CheckSpec
}

func newPingProbe(spec CheckSpec) *pingProbe { return &pingProbe{spec: spec} }

func (p *pingProbe) Name() string   { return "ping" }
func (p *pingProbe) Target() string { return p.spec.Target }
func (p *pingProbe) Interval() time.Duration {
	if p.spec.Interval > 0 {
		return p.spec.Interval.D()
	}
	return 30 * time.Second
}

func (p *pingProbe) Run(ctx context.Context) Result {
	count := p.spec.Count
	if count <= 0 {
		count = 5
	}
	host := ping.NormalizeHost(p.spec.Target, ping.DefaultPort)
	opt := ping.Options{Host: host, Count: count, Timeout: 2 * time.Second, Interval: 300 * time.Millisecond}

	var samples []ping.Sample
	for s := range ping.Probe(ctx, opt) {
		samples = append(samples, s)
	}
	res := ping.Summarize(host, count, samples)
	return Result{Check: "ping", Target: p.spec.Target, Alerts: evalPing(p.spec, res)}
}

// evalPing is the pure threshold check: it turns a ping result into alerts.
// Total loss is always critical (host unreachable); otherwise latency and loss
// thresholds each raise a warning when set and exceeded.
func evalPing(spec CheckSpec, res ping.Result) []Alert {
	now := time.Now()
	var alerts []Alert

	if res.Received == 0 {
		return []Alert{{
			Time: now, Check: "ping", Target: spec.Target, Severity: SevCrit,
			Title:  "хост недоступен",
			Detail: fmt.Sprintf("потери 100%% (%d/%d)", res.Received, res.Sent),
		}}
	}
	if spec.MaxLatency > 0 && res.AvgMs > float64(spec.MaxLatency.D().Milliseconds()) {
		alerts = append(alerts, Alert{
			Time: now, Check: "ping", Target: spec.Target, Severity: SevWarn,
			Title:  "высокая задержка",
			Detail: fmt.Sprintf("средняя %.1f мс > порога %d мс", res.AvgMs, spec.MaxLatency.D().Milliseconds()),
		})
	}
	if spec.MaxLoss > 0 && res.LossPct > spec.MaxLoss {
		alerts = append(alerts, Alert{
			Time: now, Check: "ping", Target: spec.Target, Severity: SevWarn,
			Title:  "потери пакетов",
			Detail: fmt.Sprintf("%.0f%% > порога %.0f%%", res.LossPct, spec.MaxLoss),
		})
	}
	return alerts
}
