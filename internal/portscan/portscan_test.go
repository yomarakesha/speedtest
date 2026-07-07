package portscan

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		err  bool
	}{
		{"80", []int{80}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"1-5", []int{1, 2, 3, 4, 5}, false},
		{"443,1-3,443", []int{1, 2, 3, 443}, false}, // dedup + sort
		{"5-1", []int{1, 2, 3, 4, 5}, false},        // reversed range
		{"", nil, true},
		{"0", nil, true},
		{"70000", nil, true},
		{"a-b", nil, true},
	}
	for _, c := range cases {
		got, err := parsePorts(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parsePorts(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePorts(%q): unexpected error %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHostsInCIDR(t *testing.T) {
	hosts, err := hostsInCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 4 addrs; network + broadcast dropped -> .1 and .2.
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hostsInCIDR(/30) = %v, want %v", hosts, want)
	}

	if _, err := hostsInCIDR("10.0.0.0/8"); err == nil {
		t.Errorf("expected error for oversized subnet")
	}
	if _, err := hostsInCIDR("not-a-cidr"); err == nil {
		t.Errorf("expected error for invalid CIDR")
	}
}

func TestFormatPorts(t *testing.T) {
	in := []PortInfo{{Port: 22, Service: "ssh"}, {Port: 9999, Service: ""}}
	if got, want := formatPorts(in), "22(ssh) 9999"; got != want {
		t.Errorf("formatPorts = %q, want %q", got, want)
	}
}

func TestVendorForMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want string
	}{
		{"00-14-51-aa-bb-cc", "Apple"},
		{"b8:27:eb:11:22:33", "RaspberryPi"},
		{"ff:ff:ff:00:00:00", ""},
		{"short", ""},
	}
	for _, c := range cases {
		if got := vendorForMAC(c.mac); got != c.want {
			t.Errorf("vendorForMAC(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

func TestParseARP(t *testing.T) {
	// Windows-style and Unix-style lines mixed.
	sample := `
Interface: 192.168.1.5 --- 0x2
  Internet Address      Physical Address      Type
  192.168.1.1           00-14-51-aa-bb-cc     dynamic
? (192.168.1.20) at b8:27:eb:11:22:33 [ether] on eth0
  224.0.0.22            01-00-5e-00-00-16     static
`
	got := parseARP(sample)
	if got["192.168.1.1"] != "00:14:51:aa:bb:cc" {
		t.Errorf("windows row: got %q", got["192.168.1.1"])
	}
	if got["192.168.1.20"] != "b8:27:eb:11:22:33" {
		t.Errorf("unix row: got %q", got["192.168.1.20"])
	}
}

func TestToPortInfos(t *testing.T) {
	got := toPortInfos([]int{22, 12345})
	want := []PortInfo{{Port: 22, Service: "ssh"}, {Port: 12345, Service: ""}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("toPortInfos = %v, want %v", got, want)
	}
}
