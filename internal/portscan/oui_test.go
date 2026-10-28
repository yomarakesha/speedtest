package portscan

import "testing"

func TestParseOUILine(t *testing.T) {
	cases := []struct {
		line, prefix, vendor string
		ok                   bool
	}{
		// Nmap nmap-mac-prefixes format.
		{"000B82 Grandstream Networks", "000B82", "Grandstream Networks", true},
		// Wireshark manuf: prefix, short, long (tab-separated).
		{"00:0B:82\tGrandstm\tGrandstream Networks, Inc.", "000B82", "Grandstream Networks, Inc.", true},
		// Masked prefix, /24 accepted.
		{"C0:74:AD:00:00:00/24\tUbiquiti", "C074AD", "Ubiquiti", true},
		// Masked prefix other than /24 rejected (can't key on 3 bytes).
		{"28:6F:B9:00:00:00/28\tNokia", "", "", false},
		{"# a comment", "", "", false},
		{"", "", "", false},
		{"deadbeef", "", "", false}, // single token, no vendor
	}
	for _, c := range cases {
		p, v, ok := parseOUILine(c.line)
		if ok != c.ok || p != c.prefix || v != c.vendor {
			t.Errorf("parseOUILine(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.line, p, v, ok, c.prefix, c.vendor, c.ok)
		}
	}
}
