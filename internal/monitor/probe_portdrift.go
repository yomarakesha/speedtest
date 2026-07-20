package monitor

import (
	"context"
	"fmt"
	"time"

	"speedtest/internal/portscan"
)

// portdriftProbe scans a host's ports each pass and alerts when the open set
// changes versus the last saved baseline (a port opened or closed).
type portdriftProbe struct {
	spec CheckSpec
}

func newPortdriftProbe(spec CheckSpec) *portdriftProbe { return &portdriftProbe{spec: spec} }

func (p *portdriftProbe) Name() string   { return "portdrift" }
func (p *portdriftProbe) Target() string { return p.spec.Target }
func (p *portdriftProbe) Interval() time.Duration {
	if p.spec.Interval > 0 {
		return p.spec.Interval.D()
	}
	return 5 * time.Minute
}

// portdriftKey namespaces the baseline file per target and port spec.
func portdriftKey(spec CheckSpec) string {
	return "portdrift-" + spec.Target + "-" + portSpecOrDefault(spec)
}

func portSpecOrDefault(spec CheckSpec) string {
	if spec.Ports != "" {
		return spec.Ports
	}
	return "1-1024"
}

func (p *portdriftProbe) Run(ctx context.Context) Result {
	open, err := portscan.ScanOpenPorts(p.spec.Target, portSpecOrDefault(p.spec), 500*time.Millisecond, 500)
	if err != nil {
		return Result{Check: "portdrift", Target: p.spec.Target, Err: err}
	}
	open = sortInts(open)

	key := portdriftKey(p.spec)
	var baseline []int
	hadBaseline := LoadState(key, &baseline)

	alerts := evalPortDrift(p.spec, baseline, open, hadBaseline)

	if err := SaveState(key, open); err != nil {
		return Result{Check: "portdrift", Target: p.spec.Target, Err: err, Alerts: alerts}
	}
	return Result{Check: "portdrift", Target: p.spec.Target, Alerts: alerts}
}

// evalPortDrift compares the previous open-port set with the current one and
// emits an alert per port that opened or closed. The first run (no baseline
// yet) records silently — there is nothing to compare against.
func evalPortDrift(spec CheckSpec, prev, cur []int, hadBaseline bool) []Alert {
	if !hadBaseline {
		return nil
	}
	now := time.Now()
	prevSet := make(map[int]bool, len(prev))
	for _, p := range prev {
		prevSet[p] = true
	}
	curSet := make(map[int]bool, len(cur))
	for _, p := range cur {
		curSet[p] = true
	}

	var alerts []Alert
	for _, p := range cur {
		if !prevSet[p] {
			alerts = append(alerts, Alert{
				Time: now, Check: "portdrift", Target: spec.Target, Severity: SevWarn,
				Title:  fmt.Sprintf("порт %d открылся", p),
				Detail: "ранее был закрыт",
			})
		}
	}
	for _, p := range prev {
		if !curSet[p] {
			alerts = append(alerts, Alert{
				Time: now, Check: "portdrift", Target: spec.Target, Severity: SevInfo,
				Title:  fmt.Sprintf("порт %d закрылся", p),
				Detail: "ранее был открыт",
			})
		}
	}
	return alerts
}
