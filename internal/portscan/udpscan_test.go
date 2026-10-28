package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseUDPSpec(t *testing.T) {
	if p, err := parseUDPSpec(""); err != nil || p != nil {
		t.Errorf("parseUDPSpec(\"\") = %v, %v; want nil, nil", p, err)
	}
	if p, err := parseUDPSpec("common"); err != nil || len(p) == 0 {
		t.Errorf("parseUDPSpec(common) = %v, %v; want the built-in set", p, err)
	}
	p, err := parseUDPSpec("53,161")
	if err != nil || len(p) != 2 || p[0] != 53 || p[1] != 161 {
		t.Errorf("parseUDPSpec(53,161) = %v, %v; want [53 161]", p, err)
	}
	if _, err := parseUDPSpec("nonsense"); err == nil {
		t.Error("parseUDPSpec on garbage returned no error")
	}
}

func TestUDPProbePayloadsAreWellFormed(t *testing.T) {
	// Each mapped probe must carry a non-empty, read-only payload and a label.
	for port, pr := range udpProbes {
		if pr.service == "" {
			t.Errorf("UDP probe for port %d has no service label", port)
		}
		if len(pr.payload) == 0 {
			t.Errorf("UDP probe for port %d has an empty payload", port)
		}
	}
}

func TestScanUDPClosedPortIsNotOpen(t *testing.T) {
	// A localhost UDP port with nothing bound should come back closed (ICMP
	// unreachable) or open|filtered — never a false "open".
	res := ScanUDP(context.Background(), "127.0.0.1", []int{9}, 300*time.Millisecond, 4)
	if len(res) != 1 {
		t.Fatalf("ScanUDP returned %d results, want 1", len(res))
	}
	if res[0].State == UDPOpen {
		t.Errorf("unbound UDP port reported as open: %+v", res[0])
	}
}

func TestScanUDPDetectsAResponder(t *testing.T) {
	// A UDP listener that echoes back must be classified open.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind UDP listener: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	res := ScanUDP(context.Background(), "127.0.0.1", []int{port}, time.Second, 4)
	if len(res) != 1 || res[0].State != UDPOpen {
		t.Errorf("ScanUDP against an echo responder = %+v, want state open", res)
	}
}

func TestShortHexCaps(t *testing.T) {
	long := make([]byte, 64)
	if got := shortHex(long); len(got) != 32 { // 16 bytes * 2 hex chars
		t.Errorf("shortHex length = %d, want 32", len(got))
	}
}
