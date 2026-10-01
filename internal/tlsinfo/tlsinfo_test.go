package tlsinfo

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com:443",
		"example.com:8443": "example.com:8443",
		"10.0.0.1":         "10.0.0.1:443",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInspectLocalServer runs entirely against a loopback TLS test server
// with a self-signed certificate, so it needs no real network access. It
// confirms the handshake still completes (and the cert is still reported)
// despite the chain not being trusted.
func TestInspectLocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	hostport := srv.Listener.Addr().String()
	res, err := Inspect(hostport, 2*time.Second)
	if err != nil {
		t.Fatalf("Inspect: unexpected error: %v", err)
	}
	if res.Version == "" {
		t.Error("Version is empty")
	}
	if res.CipherSuite == "" {
		t.Error("CipherSuite is empty")
	}
	if res.VerifyError == "" {
		t.Error("expected VerifyError for self-signed cert, got none")
	}
	if res.HandshakeMs <= 0 {
		t.Error("HandshakeMs should be > 0")
	}
}
