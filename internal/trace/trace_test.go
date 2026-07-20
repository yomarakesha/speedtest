package trace

import (
	"context"
	"testing"
	"time"
)

func TestTrimDot(t *testing.T) {
	cases := map[string]string{
		"host.example.com.": "host.example.com",
		"host.example.com":  "host.example.com",
		"":                  "",
		".":                 "",
	}
	for in, want := range cases {
		if got := trimDot(in); got != want {
			t.Errorf("trimDot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolverCacheAndEmpty(t *testing.T) {
	r := newResolver()
	if got := r.get(""); got != "" {
		t.Errorf(`get("") = %q, want ""`, got)
	}
	if got := r.get("203.0.113.7"); got != "" {
		t.Errorf("unrequested IP should have no name, got %q", got)
	}
}

// TestTraceReachesLoopback runs the full TTL-walk loop against 127.0.0.1 under a
// short deadline: it must resolve, emit at least one hop snapshot, and return
// without error when the context expires. probeHop itself is platform-specific
// and may report loss without ICMP privileges — the loop must cope either way.
func TestTraceReachesLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	var snapshots int
	var lastLen int
	err := Trace(ctx, Options{
		Host: "127.0.0.1", MaxHops: 3, Timeout: 100 * time.Millisecond, Interval: 50 * time.Millisecond,
	}, func(hops []Hop) {
		snapshots++
		lastLen = len(hops)
	})
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if snapshots == 0 || lastLen == 0 {
		t.Errorf("expected hop snapshots, got snapshots=%d lastLen=%d", snapshots, lastLen)
	}
}

func TestTraceBadHost(t *testing.T) {
	err := Trace(context.Background(), Options{Host: "this.host.does.not.exist.invalid"}, nil)
	if err == nil {
		t.Fatal("expected a resolve error for an invalid host")
	}
}
