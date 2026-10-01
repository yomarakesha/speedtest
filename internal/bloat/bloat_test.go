package bloat

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestGrade(t *testing.T) {
	cases := []struct {
		ms   float64
		want string
	}{
		{0, "A"},
		{4.9, "A"},
		{5, "B"},
		{29.9, "B"},
		{30, "C"},
		{59.9, "C"},
		{60, "D"},
		{199.9, "D"},
		{200, "F"},
		{500, "F"},
	}
	for _, c := range cases {
		if got := Grade(c.ms); got != c.want {
			t.Errorf("Grade(%v) = %q, want %q", c.ms, got, c.want)
		}
	}
}

// TestRunLocalServer exercises the full baseline+loaded flow against a
// loopback HTTP server, so it needs no real network access.
func TestRunLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1<<16))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}

	opt := Options{
		Host:          host,
		Port:          port,
		DownloadHost:  srv.Listener.Addr().String(),
		Duration:      300 * time.Millisecond,
		BaselineCount: 3,
		PingTimeout:   500 * time.Millisecond,
		PingInterval:  20 * time.Millisecond,
	}

	res, err := Run(context.Background(), opt)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if res.BaselineSamples == 0 {
		t.Error("expected at least one baseline sample")
	}
	if res.Grade == "" {
		t.Error("expected a non-empty grade")
	}
}
