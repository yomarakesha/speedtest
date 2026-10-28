package monitor

import (
	"testing"
	"time"

	"speedtest/internal/audit"
	"speedtest/internal/bwmon"
	"speedtest/internal/ping"
)

func TestEvalPing(t *testing.T) {
	spec := CheckSpec{Target: "h", MaxLatency: Duration(50 * time.Millisecond), MaxLoss: 2}

	// unreachable -> single critical alert
	if a := evalPing(spec, ping.Result{Sent: 5, Received: 0, LossPct: 100}); len(a) != 1 || a[0].Severity != SevCrit {
		t.Errorf("unreachable: want 1 crit, got %+v", a)
	}
	// healthy -> no alerts
	if a := evalPing(spec, ping.Result{Sent: 5, Received: 5, AvgMs: 10, LossPct: 0}); len(a) != 0 {
		t.Errorf("healthy: want 0, got %+v", a)
	}
	// high latency -> warn
	if a := evalPing(spec, ping.Result{Sent: 5, Received: 5, AvgMs: 120, LossPct: 0}); len(a) != 1 || a[0].Severity != SevWarn {
		t.Errorf("latency: want 1 warn, got %+v", a)
	}
	// loss over threshold -> warn
	if a := evalPing(spec, ping.Result{Sent: 5, Received: 4, AvgMs: 10, LossPct: 20}); len(a) != 1 {
		t.Errorf("loss: want 1, got %+v", a)
	}
	// both breaches -> two alerts
	if a := evalPing(spec, ping.Result{Sent: 5, Received: 3, AvgMs: 200, LossPct: 40}); len(a) != 2 {
		t.Errorf("both: want 2, got %+v", a)
	}
	// thresholds unset -> never alerts on a reachable host
	if a := evalPing(CheckSpec{Target: "h"}, ping.Result{Sent: 5, Received: 5, AvgMs: 9999, LossPct: 99}); len(a) != 0 {
		t.Errorf("no thresholds: want 0, got %+v", a)
	}
}

func TestEvalPortDrift(t *testing.T) {
	spec := CheckSpec{Target: "h"}

	// first run (no baseline) records silently
	if a := evalPortDrift(spec, nil, []int{22, 80}, false); len(a) != 0 {
		t.Errorf("first run: want 0, got %+v", a)
	}
	// unchanged -> no alerts
	if a := evalPortDrift(spec, []int{22, 80}, []int{22, 80}, true); len(a) != 0 {
		t.Errorf("unchanged: want 0, got %+v", a)
	}
	// port opened -> warn
	a := evalPortDrift(spec, []int{22}, []int{22, 3389}, true)
	if len(a) != 1 || a[0].Severity != SevWarn {
		t.Fatalf("opened: want 1 warn, got %+v", a)
	}
	// port closed -> info
	a = evalPortDrift(spec, []int{22, 80}, []int{22}, true)
	if len(a) != 1 || a[0].Severity != SevInfo {
		t.Fatalf("closed: want 1 info, got %+v", a)
	}
	// both -> two alerts
	if a := evalPortDrift(spec, []int{22, 80}, []int{22, 443}, true); len(a) != 2 {
		t.Errorf("open+close: want 2, got %+v", a)
	}
}

func TestEvalAuditGrade(t *testing.T) {
	spec := CheckSpec{Target: "h", MinGrade: "B"}

	// grade below minimum, no previous snapshot
	rep := audit.Report{Target: "h", Grade: "D"}
	if a := evalAuditGrade(spec, audit.Snapshot{}, false, rep); len(a) != 1 {
		t.Errorf("below min: want 1, got %+v", a)
	}
	// grade at/above minimum, no previous -> no alert
	if a := evalAuditGrade(spec, audit.Snapshot{}, false, audit.Report{Grade: "A"}); len(a) != 0 {
		t.Errorf("above min: want 0, got %+v", a)
	}
	// grade drop vs previous (still >= min) -> drop alert
	prev := audit.Snapshot{Grade: "A"}
	if a := evalAuditGrade(spec, prev, true, audit.Report{Grade: "B"}); len(a) != 1 {
		t.Errorf("drop A->B: want 1, got %+v", a)
	}
	// new finding vs previous -> alert
	prev = audit.Snapshot{Grade: "A", Findings: nil}
	cur := audit.Report{Grade: "A", Findings: []audit.Finding{{Check: "x", Title: "new", Severity: audit.Low}}}
	got := evalAuditGrade(spec, prev, true, cur)
	// grade A meets min B? no — A(5) >= B(4) so no min alert; A==A no drop; but new finding present.
	if len(got) != 1 || got[0].Title == "" {
		t.Errorf("new finding: want 1, got %+v", got)
	}
}

func TestGradeRank(t *testing.T) {
	if gradeRank("A") != 5 {
		t.Errorf("A should rank 5, got %d", gradeRank("A"))
	}
	if !(gradeRank("A") > gradeRank("B") && gradeRank("B") > gradeRank("C") && gradeRank("C") > gradeRank("F")) {
		t.Errorf("grades must order A > B > C > F")
	}
	if gradeRank("?") != -1 {
		t.Errorf("unknown grade should be -1")
	}
}

func TestEvalBandwidth(t *testing.T) {
	spec := CheckSpec{MaxMbps: 100}
	rates := []bwmon.NICRate{
		{Name: "eth0", RxMbps: 150, TxMbps: 10},
		{Name: "eth1", RxMbps: 10, TxMbps: 200},
	}
	// eth0 rx over, eth1 tx over -> 2 alerts
	if a := evalBandwidth(spec, rates); len(a) != 2 {
		t.Errorf("want 2 alerts, got %+v", a)
	}
	// iface filter narrows to eth0
	if a := evalBandwidth(CheckSpec{MaxMbps: 100, Iface: "eth0"}, rates); len(a) != 1 {
		t.Errorf("filtered: want 1, got %+v", a)
	}
	// no threshold -> no alerts
	if a := evalBandwidth(CheckSpec{}, rates); len(a) != 0 {
		t.Errorf("no threshold: want 0, got %+v", a)
	}
}

func TestRatesBetween(t *testing.T) {
	prev := []bwmon.NICSample{{Name: "eth0", Rx: 1_000_000, Tx: 0}}
	cur := []bwmon.NICSample{{Name: "eth0", Rx: 2_000_000, Tx: 0}}
	// 1 MB over 1s = 8 Mbps
	r := ratesBetween(prev, cur, time.Second)
	if len(r) != 1 || r[0].RxMbps < 7.9 || r[0].RxMbps > 8.1 {
		t.Errorf("want ~8 Mbps rx, got %+v", r)
	}
	// counter reset -> zero rate, not a spike
	r = ratesBetween([]bwmon.NICSample{{Name: "eth0", Rx: 5_000_000}}, cur, time.Second)
	if r[0].RxMbps != 0 {
		t.Errorf("reset should give 0, got %v", r[0].RxMbps)
	}
}
