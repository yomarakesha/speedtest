package audit

import (
	"net"
	"testing"
	"time"
)

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path": "example.com",
		"example.com:8443":         "example.com",
		"http://example.com":       "example.com",
		"example.com":              "example.com",
	}
	for in, want := range cases {
		if got := HostOnly(in); got != want {
			t.Errorf("HostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAuditPortsFlagsOpenRisky opens a listener, temporarily registers its port
// as risky, and checks it is reported.
func TestAuditPortsFlagsOpenRisky(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	if _, err := net.ResolveTCPAddr("tcp", ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	port = ln.Addr().(*net.TCPAddr).Port

	riskyPorts[port] = riskyPort{High, "тестовый сервис"}
	auditPortsList = append(auditPortsList, port)
	t.Cleanup(func() {
		delete(riskyPorts, port)
		auditPortsList = auditPortsList[:len(auditPortsList)-1]
	})

	findings := AuditPorts("127.0.0.1", 500*time.Millisecond)
	if !hasCheck(findings, "port.risky_exposed") {
		t.Errorf("expected risky-port finding for open port %d (%s), got %+v", port, ps, findings)
	}
}
