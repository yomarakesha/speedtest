package portscan

import (
	"net"
	"slices"
	"testing"
	"time"
)

func TestIsUnicastMACRejectsBroadcastAndMulticast(t *testing.T) {
	cases := map[string]bool{
		"00:11:22:33:44:55": true,  // ordinary NIC
		"9a:0a:00:37:65:49": true,  // locally administered, group bit clear
		"ff:ff:ff:ff:ff:ff": false, // broadcast
		"01:00:5e:00:00:16": false, // IPv4 multicast
		"33:33:00:00:00:01": false, // IPv6 multicast
		"":                  false,
		"zz:zz:zz:zz:zz:zz": false,
	}
	for mac, want := range cases {
		if got := isUnicastMAC(mac); got != want {
			t.Errorf("isUnicastMAC(%q) = %v, want %v", mac, got, want)
		}
	}
}

func TestFilterAliveFindsAListeningLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// 127.0.0.1 always answers (the loopback refuses closed ports), while the
	// TEST-NET-1 address from RFC 5737 must never be routable.
	// Some sandboxes and corporate proxies accept TCP to any address; there
	// TEST-NET-1 looks alive and the test would measure the network, not us.
	if c, err := net.DialTimeout("tcp", "192.0.2.1:80", 300*time.Millisecond); err == nil {
		c.Close()
		t.Skip("network intercepts TCP to TEST-NET-1 (192.0.2.1); liveness cannot be tested here")
	}
	hosts := []string{"127.0.0.1", "192.0.2.1"}
	got := filterAlive(hosts, 300*time.Millisecond, 16, false)

	if !slices.Contains(got, "127.0.0.1") {
		t.Errorf("filterAlive(%v) = %v, want it to contain 127.0.0.1", hosts, got)
	}
	if slices.Contains(got, "192.0.2.1") {
		t.Errorf("filterAlive(%v) = %v, want 192.0.2.1 excluded", hosts, got)
	}
}

func TestICMPAliveRejectsNonIPHost(t *testing.T) {
	if icmpAlive("not-an-ip", 100*time.Millisecond) {
		t.Error("icmpAlive(\"not-an-ip\") = true, want false")
	}
}

func TestICMPAliveAnswersOnLoopback(t *testing.T) {
	// Unprivileged ICMP may be unavailable in some sandboxes; only assert the
	// probe returns without blocking past its timeout.
	start := time.Now()
	icmpAlive("127.0.0.1", 500*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("icmpAlive took %s, want it bounded by the timeout", elapsed)
	}
}
