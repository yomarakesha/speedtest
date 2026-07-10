package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"example.com":         "https://example.com",
		"http://example.com":  "https://example.com",
		"https://example.com": "https://example.com",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditHTTPFlagsMissingHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x"}) // no Secure/HttpOnly
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use the test server's client so its self-signed cert is trusted.
	findings, err := auditHTTP(srv.URL, srv.Client(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http.no_hsts", "http.no_csp", "http.no_frame_options",
		"http.no_content_type_options", "http.no_referrer_policy",
		"http.server_version", "http.insecure_cookie",
	}
	for _, c := range want {
		if !hasCheck(findings, c) {
			t.Errorf("expected finding %q, got %+v", c, findings)
		}
	}
}

func TestAuditHTTPCleanServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := auditHTTP(srv.URL, srv.Client(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("clean server should yield no findings, got %+v", findings)
	}
	if NewReport(srv.URL, findings).Grade != "A" {
		t.Error("clean server should grade A")
	}
}
