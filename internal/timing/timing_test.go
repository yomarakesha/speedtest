package timing

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormatLinesNoTLS(t *testing.T) {
	r := Result{StatusCode: 200, DNSMs: 1.5, ConnectMs: 2.5, TLSMs: 0, TTFBMs: 10, TotalMs: 12}
	lines := FormatLines(r)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "без TLS") {
		t.Errorf("expected 'без TLS' marker for TLSMs=0, got:\n%s", joined)
	}
	if !strings.Contains(joined, "200") {
		t.Errorf("expected status code in output, got:\n%s", joined)
	}
}

func TestFormatLinesWithTLS(t *testing.T) {
	r := Result{StatusCode: 200, TLSMs: 5.5}
	joined := strings.Join(FormatLines(r), "\n")
	if strings.Contains(joined, "без TLS") {
		t.Errorf("did not expect 'без TLS' marker when TLSMs>0, got:\n%s", joined)
	}
	if !strings.Contains(joined, "5.5") {
		t.Errorf("expected TLS duration in output, got:\n%s", joined)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"example.com":         "http://example.com",
		"http://example.com":  "http://example.com",
		"https://example.com": "https://example.com",
		"10.0.0.1:8080/x":     "http://10.0.0.1:8080/x",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMeasureLocalServer exercises the real httptrace wiring against a
// loopback HTTP test server, so it needs no real network access.
func TestMeasureLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := Measure(srv.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("Measure: unexpected error: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
	if res.TLSMs != 0 {
		t.Errorf("TLSMs = %v, want 0 for plain HTTP", res.TLSMs)
	}
	if res.TotalMs <= 0 {
		t.Error("TotalMs should be > 0")
	}
	if res.TTFBMs <= 0 {
		t.Error("TTFBMs should be > 0")
	}
}
