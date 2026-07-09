package ping

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"192.168.1.1":     "192.168.1.1:80",
		"example.com:443": "example.com:443",
		"10.0.0.5:22":     "10.0.0.5:22",
	}
	for in, want := range cases {
		if got := NormalizeHost(in, 80); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarize(t *testing.T) {
	samples := []Sample{
		{Seq: 1, RTTMs: 10},
		{Seq: 2, Err: errors.New("timeout")},
		{Seq: 3, RTTMs: 30},
		{Seq: 4, RTTMs: 20},
	}
	res := Summarize("h:80", 4, samples)
	if res.Sent != 4 || res.Received != 3 {
		t.Fatalf("sent/received = %d/%d, want 4/3", res.Sent, res.Received)
	}
	if res.MinMs != 10 || res.MaxMs != 30 || res.AvgMs != 20 {
		t.Errorf("min/avg/max = %v/%v/%v, want 10/20/30", res.MinMs, res.AvgMs, res.MaxMs)
	}
	if res.LossPct != 25 {
		t.Errorf("loss = %v, want 25", res.LossPct)
	}
}

func TestProbeCountAndCancel(t *testing.T) {
	// Count-limited run against an unroutable address yields Count samples.
	opt := Options{Host: "192.0.2.1:9", Count: 3, Timeout: 100 * time.Millisecond, Interval: time.Millisecond}
	n := 0
	for range Probe(context.Background(), opt) {
		n++
	}
	if n != 3 {
		t.Fatalf("got %d samples, want 3", n)
	}

	// Cancelling stops an infinite run.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	got := 0
	for range Probe(ctx, Options{Host: "192.0.2.1:9", Count: 0, Timeout: 50 * time.Millisecond, Interval: time.Millisecond}) {
		got++
		if got > 1000 {
			t.Fatal("infinite probe did not stop on context cancel")
		}
	}
}
