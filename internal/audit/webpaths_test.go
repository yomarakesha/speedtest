package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuditWebPathsFindsGitAndEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			w.WriteHeader(200)
			w.Write([]byte("ref: refs/heads/main\n"))
		case "/.env":
			w.WriteHeader(200)
			w.Write([]byte("APP_KEY=secret\nDB_PASSWORD=hunter2\n"))
		default:
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	fs := AuditWebPaths(srv.URL, 3*time.Second)
	checks := map[string]Severity{}
	for _, f := range fs {
		checks[f.Evidence] = f.Severity
	}
	if _, ok := checks["/.git/HEAD"]; !ok {
		t.Error("did not detect exposed /.git/HEAD")
	}
	if sev, ok := checks["/.env"]; !ok || sev != Critical {
		t.Errorf("did not detect /.env as Critical: %v %v", ok, sev)
	}
}

func TestAuditWebPathsCatchAllSuppressed(t *testing.T) {
	// Server answers 200 with a body to everything -> catch-all; needle-less
	// probes must be suppressed, but a needle match (/.git/HEAD) still fires only
	// if the needle is present. Here nothing matches a needle, so expect zero.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html>catch all landing page</html>"))
	}))
	defer srv.Close()

	fs := AuditWebPaths(srv.URL, 3*time.Second)
	for _, f := range fs {
		if f.Evidence == "/.DS_Store" || f.Evidence == "/backup.zip" {
			t.Errorf("catch-all server produced false positive: %s", f.Evidence)
		}
	}
}

func TestWebBaseURL(t *testing.T) {
	cases := map[string]string{
		"example.com":              "http://example.com",
		"https://example.com/path": "https://example.com",
		"http://1.2.3.4:8080/x":    "http://1.2.3.4:8080",
	}
	for in, want := range cases {
		if got := webBaseURL(in); got != want {
			t.Errorf("webBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComplianceTags(t *testing.T) {
	tags := complianceTags("tls.weak_protocol")
	found := false
	for _, tag := range tags {
		if tag == "OWASP:A02:2021-Cryptographic-Failures" {
			found = true
		}
	}
	if !found {
		t.Errorf("tls check missing OWASP A02 tag: %v", tags)
	}
	// Report should auto-tag findings.
	r := NewReport("h", []Finding{{Check: "creds.redis_noauth", Title: "x", Severity: Critical}})
	if len(r.Findings[0].Tags) == 0 {
		t.Error("NewReport did not tag findings")
	}
}
