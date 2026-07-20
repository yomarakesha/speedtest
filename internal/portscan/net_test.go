package portscan

import (
	"slices"
	"testing"
)

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
