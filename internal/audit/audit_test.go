package audit

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestGrade(t *testing.T) {
	cases := []struct {
		name string
		sev  []Severity
		want string
	}{
		{"empty", nil, "A"},
		{"info only", []Severity{Info, Info}, "A"},
		{"low", []Severity{Info, Low}, "B"},
		{"medium", []Severity{Low, Medium}, "C"},
		{"high", []Severity{Medium, High}, "D"},
		{"critical", []Severity{High, Critical}, "F"},
		{"worst wins", []Severity{Critical, Info, Low}, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var fs []Finding
			for _, s := range c.sev {
				fs = append(fs, Finding{Severity: s})
			}
			if got := grade(fs); got != c.want {
				t.Errorf("grade(%v) = %q, want %q", c.sev, got, c.want)
			}
		})
	}
}

func TestNewReportSortsBySeverity(t *testing.T) {
	r := NewReport("x", []Finding{
		{Check: "a", Severity: Low},
		{Check: "b", Severity: Critical},
		{Check: "c", Severity: Medium},
	})
	if r.Findings[0].Severity != Critical || r.Findings[2].Severity != Low {
		t.Fatalf("findings not sorted by descending severity: %+v", r.Findings)
	}
	if r.Grade != "F" {
		t.Errorf("grade = %q, want F", r.Grade)
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	b, err := json.Marshal(High)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"высокая"` {
		t.Errorf("Marshal(High) = %s", b)
	}
}

func TestSplitHostPort(t *testing.T) {
	h, addr := splitHostPort("example.com", 443)
	if h != "example.com" || addr != "example.com:443" {
		t.Errorf("got %q, %q", h, addr)
	}
	h, addr = splitHostPort("example.com:8443", 443)
	if h != "example.com" || addr != "example.com:8443" {
		t.Errorf("got %q, %q", h, addr)
	}
}

func TestIsWeakSignature(t *testing.T) {
	if !isWeakSignature(x509.SHA1WithRSA) {
		t.Error("SHA1WithRSA should be weak")
	}
	if isWeakSignature(x509.SHA256WithRSA) {
		t.Error("SHA256WithRSA should not be weak")
	}
}

// TestAuditTLSAgainstLocalServer spins up a TLS server with a self-signed,
// short-lived cert and checks the audit flags the untrusted chain.
func TestAuditTLSAgainstLocalServer(t *testing.T) {
	cert := selfSignedCert(t, "localhost", time.Now().Add(24*time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	findings, err := AuditTLS("localhost:"+port, 443, 4*time.Second)
	if err != nil {
		t.Fatalf("AuditTLS: %v", err)
	}
	if !hasCheck(findings, "tls.untrusted_chain") {
		t.Errorf("expected untrusted_chain finding, got %+v", findings)
	}
}

func hasCheck(fs []Finding, check string) bool {
	for _, f := range fs {
		if f.Check == check {
			return true
		}
	}
	return false
}
