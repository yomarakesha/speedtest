package portscan

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveTargetPassesThroughIPLiterals(t *testing.T) {
	for _, ip := range []string{"192.168.1.1", "8.8.8.8", "::1"} {
		got, err := ResolveTarget(context.Background(), ip, time.Second)
		if err != nil || got != ip {
			t.Errorf("ResolveTarget(%q) = %q, %v; want %q, nil", ip, got, err, ip)
		}
	}
}

func TestResolveTargetResolvesLocalhostToIPv4(t *testing.T) {
	got, err := ResolveTarget(context.Background(), "localhost", 5*time.Second)
	if err != nil {
		t.Fatalf("ResolveTarget(localhost): %v", err)
	}
	if got != "127.0.0.1" {
		t.Errorf("ResolveTarget(localhost) = %q, want 127.0.0.1", got)
	}
}

func TestResolveTargetReportsUnresolvableName(t *testing.T) {
	_, err := ResolveTarget(context.Background(), "no-such-host.invalid", 5*time.Second)
	if err == nil {
		t.Fatal("ResolveTarget on an unresolvable name returned no error")
	}
}

func TestDescribeTarget(t *testing.T) {
	if got := describeTarget("8.8.8.8", "8.8.8.8"); got != "8.8.8.8" {
		t.Errorf("describeTarget(ip, ip) = %q, want the bare IP", got)
	}
	if got := describeTarget("example.com", "93.184.216.34"); got != "example.com (93.184.216.34)" {
		t.Errorf("describeTarget(name, ip) = %q, want \"example.com (93.184.216.34)\"", got)
	}
}

func TestLoopbackWarning(t *testing.T) {
	if got := loopbackWarning("example.com", "93.184.216.34"); got != "" {
		t.Errorf("loopbackWarning on a routable address = %q, want empty", got)
	}
	if got := loopbackWarning("127.0.0.1", "127.0.0.1"); got != "" {
		t.Errorf("loopbackWarning on a deliberate localhost scan = %q, want empty", got)
	}
	got := loopbackWarning("example.com", "127.0.0.1")
	if !strings.Contains(got, "example.com") || !strings.Contains(got, "127.0.0.1") {
		t.Errorf("loopbackWarning on a hijacked name = %q, want it to name both the host and the address", got)
	}
}

func TestHostnameForKeepsTheNameTheCallerGave(t *testing.T) {
	if got := hostnameFor("example.com", "93.184.216.34"); got != "example.com" {
		t.Errorf("hostnameFor(name, ip) = %q, want the name", got)
	}
}

func TestRouteToCIDR(t *testing.T) {
	cases := []struct {
		dest, mask, want string
	}{
		{"192.168.1.0", "255.255.255.0", "192.168.1.0/24"},
		{"10.0.0.0", "255.0.0.0", "10.0.0.0/8"},
		{"172.16.5.0", "255.255.255.128", "172.16.5.0/25"},
		{"0.0.0.0", "0.0.0.0", "0.0.0.0/0"},
		{"bad", "255.255.255.0", ""},       // invalid dest
		{"192.168.1.0", "255.0.255.0", ""}, // non-contiguous mask
		{"::1", "255.255.255.0", ""},       // not IPv4
	}
	for _, c := range cases {
		if got := routeToCIDR(c.dest, c.mask); got != c.want {
			t.Errorf("routeToCIDR(%q,%q) = %q, want %q", c.dest, c.mask, got, c.want)
		}
	}
}

func TestUsefulSubnet(t *testing.T) {
	good := []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16"}
	for _, c := range good {
		if !usefulSubnet(c) {
			t.Errorf("usefulSubnet(%q) = false, want true", c)
		}
	}
	bad := []string{
		"",               // empty
		"0.0.0.0/0",      // default route
		"192.168.1.5/32", // host route
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"224.0.0.0/4",    // multicast
		"nonsense",       // malformed
	}
	for _, c := range bad {
		if usefulSubnet(c) {
			t.Errorf("usefulSubnet(%q) = true, want false", c)
		}
	}
}

func TestSplitCIDRs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"192.168.1.0/24", []string{"192.168.1.0/24"}},
		{"192.168.20.0/24,10.0.0.0/24", []string{"192.168.20.0/24", "10.0.0.0/24"}},
		{" 192.168.20.0/24 , 10.0.0.0/24 ", []string{"192.168.20.0/24", "10.0.0.0/24"}},
		{"10.0.0.0/24 172.16.0.0/16", []string{"10.0.0.0/24", "172.16.0.0/16"}}, // space-separated
		{"10.0.0.0/24,10.0.0.0/24", []string{"10.0.0.0/24"}},                    // dedup
		{",,10.0.0.0/24,,", []string{"10.0.0.0/24"}},                            // empty entries dropped
	}
	for _, c := range cases {
		if got := SplitCIDRs(c.in); !slices.Equal(got, c.want) {
			t.Errorf("SplitCIDRs(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseRoutesWindows(t *testing.T) {
	// Trimmed `route print -4` output.
	out := `
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.23     25
      192.168.1.0    255.255.255.0         On-link      192.168.1.23    281
       10.10.0.0      255.255.0.0      192.168.1.1     192.168.1.23     26
    192.168.1.23  255.255.255.255         On-link      192.168.1.23    281
      127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      224.0.0.0        240.0.0.0         On-link      192.168.1.23    281
===========================================================================
`
	got := parseRoutes(out, "windows")
	// Keep the two real LAN subnets; drop default, host, loopback, multicast.
	for _, want := range []string{"192.168.1.0/24", "10.10.0.0/16"} {
		if !slices.Contains(got, want) {
			t.Errorf("parseRoutes windows: missing %q in %v", want, got)
		}
	}
	for _, bad := range []string{"0.0.0.0/0", "127.0.0.0/8", "224.0.0.0/4"} {
		if slices.Contains(got, bad) {
			t.Errorf("parseRoutes windows: should not contain %q (got %v)", bad, got)
		}
	}
}

func TestParseRoutesLinux(t *testing.T) {
	out := `default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.23 metric 100
10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.2
169.254.0.0/16 dev eth0 scope link metric 1000`
	got := parseRoutes(out, "linux")
	for _, want := range []string{"192.168.1.0/24", "10.8.0.0/24"} {
		if !slices.Contains(got, want) {
			t.Errorf("parseRoutes linux: missing %q in %v", want, got)
		}
	}
	if slices.Contains(got, "169.254.0.0/16") {
		t.Errorf("parseRoutes linux: should drop link-local, got %v", got)
	}
}
