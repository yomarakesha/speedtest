package dnsbench

import (
	"reflect"
	"testing"
	"time"
)

func TestSummarizeDurations(t *testing.T) {
	avg, min, max := summarizeDurations([]time.Duration{
		10 * time.Millisecond,
		30 * time.Millisecond,
		20 * time.Millisecond,
	})
	if avg != 20 || min != 10 || max != 30 {
		t.Errorf("avg/min/max = %v/%v/%v, want 20/10/30", avg, min, max)
	}
}

func TestSummarizeDurationsEmpty(t *testing.T) {
	avg, min, max := summarizeDurations(nil)
	if avg != 0 || min != 0 || max != 0 {
		t.Errorf("avg/min/max = %v/%v/%v, want 0/0/0", avg, min, max)
	}
}

func TestParseServersDefault(t *testing.T) {
	got := parseServers("")
	if !reflect.DeepEqual(got, DefaultServers) {
		t.Error("parseServers(\"\") should return DefaultServers")
	}
}

func TestParseServersCustom(t *testing.T) {
	got := parseServers("Cloudflare=1.1.1.1, 8.8.8.8")
	want := []ServerSpec{
		{Label: "Cloudflare", Addr: "1.1.1.1"},
		{Label: "8.8.8.8", Addr: "8.8.8.8"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseServers = %+v, want %+v", got, want)
	}
}

func TestParseDomainsDefault(t *testing.T) {
	got := parseDomains("")
	if !reflect.DeepEqual(got, DefaultDomains) {
		t.Error("parseDomains(\"\") should return DefaultDomains")
	}
}

func TestParseDomainsCustom(t *testing.T) {
	got := parseDomains("a.com, b.com ,c.com")
	want := []string{"a.com", "b.com", "c.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseDomains = %v, want %v", got, want)
	}
}

// TestBenchHandlesFailure ensures a resolver that can never succeed (an
// unroutable test-net address) is reported as all-failures rather than
// aborting the whole benchmark. Uses only local/unroutable addresses, no
// real network access.
func TestBenchHandlesFailure(t *testing.T) {
	servers := []ServerSpec{{"Мёртвый", "192.0.2.1"}}
	results := Bench([]string{"example.invalid"}, servers, 200*time.Millisecond)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Failures != 1 || results[0].Total != 1 {
		t.Errorf("Failures/Total = %d/%d, want 1/1", results[0].Failures, results[0].Total)
	}
}
