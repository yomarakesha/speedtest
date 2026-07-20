package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/bwmon"
)

// bandwidthProbe samples this machine's interface counters over a short window
// and alerts when receive or transmit throughput exceeds max_mbps.
type bandwidthProbe struct {
	spec CheckSpec
}

func newBandwidthProbe(spec CheckSpec) *bandwidthProbe { return &bandwidthProbe{spec: spec} }

func (p *bandwidthProbe) Name() string   { return "bandwidth" }
func (p *bandwidthProbe) Target() string { return ifaceLabel(p.spec.Iface) }
func (p *bandwidthProbe) Interval() time.Duration {
	if p.spec.Interval > 0 {
		return p.spec.Interval.D()
	}
	return 5 * time.Second
}

// bwWindow is the delta window used to turn cumulative counters into a rate.
const bwWindow = time.Second

func (p *bandwidthProbe) Run(ctx context.Context) Result {
	prev, err := bwmon.Sample()
	if err != nil {
		return Result{Check: "bandwidth", Target: p.Target(), Err: err}
	}
	select {
	case <-ctx.Done():
		return Result{Check: "bandwidth", Target: p.Target()}
	case <-time.After(bwWindow):
	}
	cur, err := bwmon.Sample()
	if err != nil {
		return Result{Check: "bandwidth", Target: p.Target(), Err: err}
	}

	rates := ratesBetween(prev, cur, bwWindow)
	return Result{Check: "bandwidth", Target: p.Target(), Alerts: evalBandwidth(p.spec, rates)}
}

// ratesBetween converts two counter samples taken dt apart into per-interface
// Mbps rates, skipping interfaces whose counters went backwards (reset).
func ratesBetween(prev, cur []bwmon.NICSample, dt time.Duration) []bwmon.NICRate {
	secs := dt.Seconds()
	byName := make(map[string]bwmon.NICSample, len(prev))
	for _, p := range prev {
		byName[p.Name] = p
	}
	out := make([]bwmon.NICRate, 0, len(cur))
	for _, c := range cur {
		r := bwmon.NICRate{Name: c.Name, Rx: c.Rx, Tx: c.Tx}
		if p, ok := byName[c.Name]; ok && secs > 0 {
			r.RxMbps = deltaMbps(c.Rx, p.Rx, secs)
			r.TxMbps = deltaMbps(c.Tx, p.Tx, secs)
		}
		out = append(out, r)
	}
	return out
}

func deltaMbps(cur, prev uint64, secs float64) float64 {
	if cur < prev || secs <= 0 {
		return 0
	}
	return float64(cur-prev) * 8 / secs / 1e6
}

// evalBandwidth alerts for each matching interface whose rx or tx rate exceeds
// the threshold. An empty spec.Iface matches every interface.
func evalBandwidth(spec CheckSpec, rates []bwmon.NICRate) []Alert {
	if spec.MaxMbps <= 0 {
		return nil
	}
	now := time.Now()
	var alerts []Alert
	for _, r := range rates {
		if !ifaceMatch(spec.Iface, r.Name) {
			continue
		}
		if r.RxMbps > spec.MaxMbps {
			alerts = append(alerts, Alert{
				Time: now, Check: "bandwidth", Target: r.Name, Severity: SevWarn,
				Title:  "приём выше порога",
				Detail: fmt.Sprintf("%.1f Мбит/с > %.0f", r.RxMbps, spec.MaxMbps),
			})
		}
		if r.TxMbps > spec.MaxMbps {
			alerts = append(alerts, Alert{
				Time: now, Check: "bandwidth", Target: r.Name, Severity: SevWarn,
				Title:  "передача выше порога",
				Detail: fmt.Sprintf("%.1f Мбит/с > %.0f", r.TxMbps, spec.MaxMbps),
			})
		}
	}
	return alerts
}

// ifaceMatch reports whether name matches the configured filter (case-insensitive
// substring). An empty filter matches everything.
func ifaceMatch(filter, name string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(name), strings.ToLower(filter))
}

func ifaceLabel(filter string) string {
	if filter == "" {
		return "все интерфейсы"
	}
	return filter
}
