package portscan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBaseDomain(t *testing.T) {
	cases := []struct{ host, want string }{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"api.stage.example.com", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"shop.co.uk", "shop.co.uk"},       // co.uk is a public suffix, not a domain
		{"www.shop.co.uk", "shop.co.uk"},   // so the base is three labels deep
		{"a.b.shop.com.br", "shop.com.br"}, //
		{"localhost", "localhost"},         // single label stays as-is
		{"192.168.1.1", ""},                // an IP has no zone to enumerate
		{"", ""},                           //
	}
	for _, c := range cases {
		if got := baseDomain(c.host); got != c.want {
			t.Errorf("baseDomain(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestSameAddrs(t *testing.T) {
	if !sameAddrs([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Error("sameAddrs on identical sets = false, want true")
	}
	if sameAddrs([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Error("sameAddrs on differing sets = true, want false")
	}
	if sameAddrs(nil, nil) {
		t.Error("sameAddrs on two empty sets = true; an unresolved name must not count as a wildcard match")
	}
	if sameAddrs([]string{"1.1.1.1"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Error("sameAddrs on different lengths = true, want false")
	}
}

func TestNormalizeName(t *testing.T) {
	if got := normalizeName("  WWW.Example.COM.  "); got != "www.example.com" {
		t.Errorf("normalizeName = %q, want www.example.com", got)
	}
}

func TestEnumSubdomainsIgnoresNamesOutsideTheZone(t *testing.T) {
	// A CDN certificate lists names of other tenants; only the scanned zone's own
	// names may end up in the result.
	res := EnumSubdomains(context.Background(), SubdomainOptions{
		Domain:   "no-such-zone-for-tests.invalid",
		Timeout:  200 * time.Millisecond,
		Workers:  4,
		Wordlist: []string{"www"},
	})
	if res.Base != "no-such-zone-for-tests.invalid" {
		t.Errorf("Base = %q, want the scanned zone", res.Base)
	}
	for _, s := range res.Found {
		t.Errorf("unresolvable zone yielded %q", s.Name)
	}
}

func TestEnumSubdomainsRejectsIPTargets(t *testing.T) {
	res := EnumSubdomains(context.Background(), SubdomainOptions{
		Domain: "8.8.8.8", Timeout: 200 * time.Millisecond, Wordlist: []string{"www"},
	})
	if res.Base != "" || len(res.Found) != 0 {
		t.Errorf("EnumSubdomains on an IP = %+v, want an empty result", res)
	}
}

func TestFormatAddrsKeepsTheColumnNarrow(t *testing.T) {
	if got := formatAddrs([]string{"1.1.1.1", "2.2.2.2"}); got != "1.1.1.1, 2.2.2.2" {
		t.Errorf("formatAddrs on a short set = %q, want it listed in full", got)
	}
	if got := formatAddrs([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}); got != "1.1.1.1, 2.2.2.2 +2" {
		t.Errorf("formatAddrs on a long set = %q, want the overflow counted", got)
	}
	if got := formatAddrs(nil); got != "" {
		t.Errorf("formatAddrs(nil) = %q, want empty", got)
	}
}

func TestHasLoopback(t *testing.T) {
	if !hasLoopback([]string{"93.184.216.34", "127.0.0.1"}) {
		t.Error("hasLoopback missed a localhost answer")
	}
	if hasLoopback([]string{"93.184.216.34"}) {
		t.Error("hasLoopback flagged a routable address")
	}
}

func TestParseCTEntries(t *testing.T) {
	// crt.sh returns name_value with newline-separated names, plus common_name.
	body := `[
	  {"common_name":"www.example.com","name_value":"www.example.com\n*.example.com"},
	  {"common_name":"api.example.com","name_value":"API.Example.COM\napi.example.com"}
	]`
	got := parseCTEntries(strings.NewReader(body))
	want := map[string]bool{"www.example.com": true, "*.example.com": true, "api.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("parseCTEntries returned %v, want %d distinct names", got, len(want))
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected name %q", n)
		}
	}
}

func TestParseCTEntriesHandlesGarbage(t *testing.T) {
	if got := parseCTEntries(strings.NewReader("<html>502 Bad Gateway</html>")); got != nil {
		t.Errorf("parseCTEntries on non-JSON = %v, want nil", got)
	}
}

func TestDefaultWordlistHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range defaultSubdomainWords {
		if seen[w] {
			t.Errorf("duplicate word %q in defaultSubdomainWords", w)
		}
		seen[w] = true
	}
}
