package capture

import (
	"context"
	"testing"
)

func newTestProcAcc(lookup func(string, uint16) (int, bool), name func(int) string, local ...string) *processAccumulator {
	set := map[string]bool{}
	for _, ip := range local {
		set[ip] = true
	}
	return newProcessAccumulator(set, lookup, name)
}

func TestProcessAccumulatorAttributesByLocalPort(t *testing.T) {
	lookup := func(proto string, port uint16) (int, bool) {
		if proto == "tcp" && port == 51000 {
			return 4242, true
		}
		return 0, false
	}
	names := func(pid int) string {
		if pid == 4242 {
			return "chrome.exe"
		}
		return ""
	}
	acc := newTestProcAcc(lookup, names, "192.168.1.10")

	// Outbound: local port 51000 -> remote 443 (upload).
	acc.observe("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, 1000)
	// Inbound: remote 443 -> local port 51000 (download).
	acc.observe("tcp", "8.8.8.8", 443, "192.168.1.10", 51000, 3000)

	got := acc.rates(0, 1)
	if len(got) != 1 {
		t.Fatalf("got %d processes, want 1: %+v", len(got), got)
	}
	if got[0].PID != 4242 || got[0].Name != "chrome.exe" {
		t.Errorf("process = %+v, want PID 4242/chrome.exe", got[0])
	}
	if got[0].Tx != 1000 || got[0].Rx != 3000 {
		t.Errorf("Tx/Rx = %d/%d, want 1000/3000", got[0].Tx, got[0].Rx)
	}
}

func TestProcessAccumulatorUnattributedFallsBackToSystemBucket(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observe("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, 500)

	got := acc.rates(0, 1)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].PID != 0 || got[0].Name != unattributedName {
		t.Errorf("got %+v, want PID 0 / %q", got[0], unattributedName)
	}
}

func TestProcessAccumulatorObserveOtherGoesToSystemBucket(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observeOther("192.168.1.10", "8.8.8.8", 64) // e.g. ICMP echo request

	got := acc.rates(0, 1)
	if len(got) != 1 || got[0].PID != 0 || got[0].Tx != 64 {
		t.Errorf("got %+v, want single PID-0 row with Tx=64", got)
	}
}

func TestProcessAccumulatorDropsLoopbackAndNonLocalFrames(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observe("tcp", "127.0.0.1", 1, "127.0.0.1", 2, 100) // both local
	acc.observe("tcp", "8.8.8.8", 1, "1.1.1.1", 2, 100)     // neither local
	if got := acc.rates(0, 1); len(got) != 0 {
		t.Errorf("expected no rows, got %+v", got)
	}
}

func TestProcessAccumulatorRatesSortedByTotalDescending(t *testing.T) {
	lookup := func(proto string, port uint16) (int, bool) { return int(port), true }
	acc := newTestProcAcc(lookup, nil, "10.0.0.1")
	acc.observe("tcp", "10.0.0.1", 100, "1.1.1.1", 1, 500)  // pid 100, total 500
	acc.observe("tcp", "10.0.0.1", 200, "1.1.1.1", 1, 1500) // pid 200, total 1500

	got := acc.rates(0, 1)
	if len(got) != 2 || got[0].PID != 200 || got[1].PID != 100 {
		t.Errorf("wrong order: %+v", got)
	}
	if got[0].Name != "PID 200" {
		t.Errorf("fallback name = %q, want %q", got[0].Name, "PID 200")
	}
}

func TestProcessAccumulatorRatesComputesMbps(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "10.0.0.1")
	acc.observe("tcp", "1.1.1.1", 1, "10.0.0.1", 100, 1_000_000) // 1MB inbound
	got := acc.rates(0, 1)                                       // over 1 second
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	want := 8.0 // 1,000,000 bytes * 8 / 1s / 1e6 = 8 Mbps
	if got[0].RxMbps < want-0.01 || got[0].RxMbps > want+0.01 {
		t.Errorf("RxMbps = %f, want ~%f", got[0].RxMbps, want)
	}
}

func TestStubTopProcessesUnavailable(t *testing.T) {
	if Available() {
		t.Skip("pcap build; stub test not applicable")
	}
	err := TopProcesses(context.Background(), Options{}, func([]ProcTraffic) {})
	if err != ErrUnavailable {
		t.Errorf("TopProcesses err = %v, want ErrUnavailable", err)
	}
}
