package netinfo

import (
	"reflect"
	"testing"
)

func TestParseProcNetRoute(t *testing.T) {
	sample := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wlp0s20f3\t00000000\tFE22A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"wlp0s20f3\t0022A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
	gw, err := parseProcNetRoute(sample)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gw != "192.168.34.254" {
		t.Errorf("gateway = %q, want 192.168.34.254", gw)
	}
}

func TestParseProcNetRouteNoDefault(t *testing.T) {
	sample := "Iface\tDestination\tGateway\n" +
		"wlp0s20f3\t0022A8C0\t00000000\n"
	if _, err := parseProcNetRoute(sample); err == nil {
		t.Error("expected error when no default route present")
	}
}

func TestParseResolvConf(t *testing.T) {
	sample := "# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver 1.1.1.1\n"
	got := parseResolvConf(sample)
	want := []string{"127.0.0.53", "1.1.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseResolvConf = %v, want %v", got, want)
	}
}

func TestParseDarwinRouteGet(t *testing.T) {
	sample := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n"
	if got := parseDarwinRouteGet(sample); got != "192.168.1.1" {
		t.Errorf("parseDarwinRouteGet = %q, want 192.168.1.1", got)
	}
}

func TestParseWindowsRoutePrint(t *testing.T) {
	sample := "IPv4 Route Table\n" +
		"===========================================================================\n" +
		"Active Routes:\n" +
		"Network Destination        Netmask          Gateway       Interface  Metric\n" +
		"          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.23     25\n"
	if got := parseWindowsRoutePrint(sample); got != "192.168.1.1" {
		t.Errorf("parseWindowsRoutePrint = %q, want 192.168.1.1", got)
	}
}

func TestParseWindowsDNS(t *testing.T) {
	sample := "   DNS Servers . . . . . . . . . . . : 1.1.1.1\n" +
		"                                       8.8.8.8\n" +
		"   NetBIOS over Tcpip. . . . . . . : Enabled\n"
	got := parseWindowsDNS(sample)
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseWindowsDNS = %v, want %v", got, want)
	}
}

func TestHasIPv6(t *testing.T) {
	cases := []struct {
		name string
		ifs  []IfaceInfo
		want bool
	}{
		{"none", []IfaceInfo{{IPs: []string{"192.168.1.5"}}}, false},
		{"link-local only", []IfaceInfo{{IPs: []string{"fe80::1"}}}, false},
		{"global", []IfaceInfo{{IPs: []string{"192.168.1.5", "2001:db8::1"}}}, true},
	}
	for _, c := range cases {
		if got := hasIPv6(c.ifs); got != c.want {
			t.Errorf("%s: hasIPv6 = %v, want %v", c.name, got, c.want)
		}
	}
}
