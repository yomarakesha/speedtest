package portscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// tlsPorts are ports where a TLS handshake is attempted first.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 853: true, 993: true, 995: true,
	2376: true, 4443: true, 5986: true, 6443: true, 8443: true, 9443: true, 10250: true,
}

// httpPorts are ports where a plain HTTP request is sent when the server stays
// silent after connect.
var httpPorts = map[int]bool{
	80: true, 81: true, 591: true, 3000: true, 5000: true, 7080: true, 8000: true,
	8008: true, 8080: true, 8081: true, 8088: true, 8096: true, 8888: true,
	9000: true, 9090: true, 9200: true, 5601: true, 15672: true, 32400: true,
}

// GrabBanner identifies what is listening on host:port. It tries, in order:
// a TLS handshake (on TLS ports), the server's own greeting (SSH, FTP, SMTP,
// ...), and an HTTP HEAD request. Returns a short one-line description, or ""
// when nothing could be learned within timeout.
func GrabBanner(host string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	if tlsPorts[port] {
		if s := tlsBanner(addr, host, timeout); s != "" {
			return s
		}
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Many protocols greet first; give them a moment.
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		return cleanBanner(string(buf[:n]))
	}

	// Silent server: try HTTP on anything that might speak it.
	if httpPorts[port] || !tlsPorts[port] {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: speedtest/1.0\r\n\r\n", host)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err == nil {
			resp.Body.Close()
			return httpSummary(resp)
		}
	}
	return ""
}

// tlsBanner performs a TLS handshake and summarizes the certificate.
func tlsBanner(addr, host string, timeout time.Duration) string {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // identification only, not trust
		ServerName:         host,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()
	st := conn.ConnectionState()
	out := tls.VersionName(st.Version)
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		out += " cert=" + stripCtrl(c.Subject.CommonName)
		if d := time.Until(c.NotAfter); d < 0 {
			out += " (просрочен)"
		} else if d < 30*24*time.Hour {
			out += fmt.Sprintf(" (истекает через %d дн)", int(d.Hours()/24))
		}
	}
	// Ask over HTTP too: the Server header is often the most telling.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: speedtest/1.0\r\n\r\n", host)
	if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		resp.Body.Close()
		out += " " + httpSummary(resp)
	}
	return out
}

func httpSummary(resp *http.Response) string {
	// Server / X-Powered-By are attacker-controlled: strip control bytes so the
	// values cannot inject terminal-escape sequences into the audit output.
	s := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if srv := stripCtrl(resp.Header.Get("Server")); srv != "" {
		s += " " + srv
	}
	if p := stripCtrl(resp.Header.Get("X-Powered-By")); p != "" {
		s += " (" + p + ")"
	}
	return s
}

// stripCtrl keeps the first line and drops control/escape bytes (ANSI, CR, NUL,
// DEL). It is the shared sanitizer for any remote-supplied banner field.
func stripCtrl(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// cleanBanner strips control bytes and trims to a sane length.
func cleanBanner(s string) string {
	s = stripCtrl(s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
