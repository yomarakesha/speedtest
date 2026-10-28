package capture

import (
	"testing"
	"time"
)

// newTestAcc builds an accumulator with a fixed local IP set for deterministic
// tests (avoids depending on the host's real interfaces).
func newTestAcc(local ...string) *accumulator {
	set := map[string]bool{}
	for _, ip := range local {
		set[ip] = true
	}
	return &accumulator{local: set, byIP: map[string]*Talker{}}
}

func TestAccumulatorCreditsRemotePeers(t *testing.T) {
	acc := newTestAcc("192.168.1.10")

	// Download from 8.8.8.8 (peer -> us) and upload to it (us -> peer).
	acc.observe("8.8.8.8", "aa:bb:cc:00:00:01", "192.168.1.10", "aa:bb:cc:00:00:02", 1000)
	acc.observe("192.168.1.10", "aa:bb:cc:00:00:02", "8.8.8.8", "aa:bb:cc:00:00:01", 500)
	// A chatty peer.
	acc.observe("1.1.1.1", "aa:bb:cc:00:00:03", "192.168.1.10", "aa:bb:cc:00:00:02", 4000)

	top := acc.top(0, false, time.Second)
	if len(top) != 2 {
		t.Fatalf("got %d talkers, want 2 (local excluded): %+v", len(top), top)
	}
	// Sorted by bytes desc: 1.1.1.1 (4000) before 8.8.8.8 (1500).
	if top[0].IP != "1.1.1.1" || top[0].Bytes != 4000 {
		t.Errorf("top[0] = %+v, want 1.1.1.1/4000", top[0])
	}
	if top[1].IP != "8.8.8.8" || top[1].Bytes != 1500 {
		t.Errorf("top[1] = %+v, want 8.8.8.8/1500", top[1])
	}
	if top[1].Packets != 2 {
		t.Errorf("8.8.8.8 packets = %d, want 2", top[1].Packets)
	}
	if top[0].MAC != "aa:bb:cc:00:00:03" {
		t.Errorf("MAC not captured: %+v", top[0])
	}
}

func TestAccumulatorExcludesLocalAndNonUnicast(t *testing.T) {
	acc := newTestAcc("192.168.1.10")
	// local <-> broadcast/multicast: nothing countable.
	acc.observe("192.168.1.10", "m1", "255.255.255.255", "ffff", 200)
	acc.observe("192.168.1.10", "m1", "224.0.0.251", "0100", 200) // mDNS multicast
	acc.observe("127.0.0.1", "lo", "127.0.0.1", "lo", 200)        // loopback
	if got := acc.top(0, false, time.Second); len(got) != 0 {
		t.Errorf("expected no talkers, got %+v", got)
	}
}

func TestAccumulatorTopLimit(t *testing.T) {
	acc := newTestAcc("10.0.0.1")
	acc.observe("10.0.0.2", "", "10.0.0.1", "", 100)
	acc.observe("10.0.0.3", "", "10.0.0.1", "", 200)
	acc.observe("10.0.0.4", "", "10.0.0.1", "", 300)
	top := acc.top(2, false, time.Second)
	if len(top) != 2 {
		t.Fatalf("got %d, want 2", len(top))
	}
	if top[0].IP != "10.0.0.4" || top[1].IP != "10.0.0.3" {
		t.Errorf("wrong top-2 ordering: %+v", top)
	}
}

func TestIsRemoteUnicast(t *testing.T) {
	yes := []string{"8.8.8.8", "192.168.1.5", "2001:4860:4860::8888"}
	for _, ip := range yes {
		if !isRemoteUnicast(ip) {
			t.Errorf("isRemoteUnicast(%q) = false, want true", ip)
		}
	}
	no := []string{"127.0.0.1", "224.0.0.251", "255.255.255.255", "0.0.0.0", "fe80::1", "notanip"}
	for _, ip := range no {
		if isRemoteUnicast(ip) {
			t.Errorf("isRemoteUnicast(%q) = true, want false", ip)
		}
	}
}

func TestStubUnavailable(t *testing.T) {
	if Available() {
		t.Skip("pcap build; stub test not applicable")
	}
	if _, err := Devices(); err != ErrUnavailable {
		t.Errorf("Devices err = %v, want ErrUnavailable", err)
	}
}
