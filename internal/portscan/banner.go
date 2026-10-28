package portscan

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// tlsPorts are ports that speak TLS immediately. GrabBanner handshakes there
// first; grabBanner skips them (a plaintext read only yields handshake noise);
// the subdomain search uses the same set to decide where a cert can be read.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 853: true, 989: true, 990: true, 993: true,
	995: true, 2376: true, 4443: true, 5986: true, 6443: true, 8443: true,
	8843: true, 8883: true, 9443: true, 10250: true, 10443: true,
}

// httpPorts are plaintext HTTP ports where a HEAD request is sent to make a
// silent server identify itself.
var httpPorts = map[int]bool{
	80: true, 81: true, 591: true, 3000: true, 5000: true, 5601: true, 7080: true,
	8000: true, 8008: true, 8080: true, 8081: true, 8088: true, 8096: true,
	8888: true, 9000: true, 9090: true, 9200: true, 15672: true, 32400: true,
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

// isUnsafeRune reports runes that must never reach the terminal from a remote
// banner: C0/C1 controls (ESC, CSI 0x9b, CR, NUL, DEL) and Unicode format
// characters (bidi overrides, zero-width) that can disguise displayed text.
func isUnsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// stripCtrl keeps the first line and drops unsafe runes. It is the shared
// sanitizer for any remote-supplied banner field.
func stripCtrl(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if isUnsafeRune(r) {
			return -1
		}
		return r
	}, s))
}

// cleanBanner strips unsafe runes and caps the length.
func cleanBanner(s string) string { return sanitizeBanner(stripCtrl(s)) }

// grabBanner opens a short-lived connection to host:port and returns the first
// line the service volunteers (for HTTP it returns the Server header, if any).
// It returns "" when nothing useful is read or the port speaks TLS.
func grabBanner(host string, port int, timeout time.Duration) string {
	if tlsPorts[port] {
		return ""
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if httpPorts[port] {
		if _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")); err != nil {
			return ""
		}
		return httpServerHeader(conn)
	}
	// Non-HTTP services (SSH, FTP, SMTP, POP3, IMAP, ...) greet on connect.
	r := bufio.NewReader(conn)
	line, _ := r.ReadString('\n')
	return sanitizeBanner(line)
}

// httpServerHeader reads an HTTP response and returns its Server header value,
// falling back to the status line when no Server header is present.
func httpServerHeader(conn net.Conn) string {
	r := bufio.NewReader(conn)
	status, _ := r.ReadString('\n')
	for {
		line, err := r.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Server") {
			return sanitizeBanner(v)
		}
	}
	return sanitizeBanner(status)
}

// sanitizeBanner trims whitespace and control characters and caps the length so
// a banner can't blow up table layout.
func sanitizeBanner(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if isUnsafeRune(r) {
			return -1
		}
		return r
	}, s))
	const max = 80
	// Cap by runes, not bytes: slicing a byte offset can split a multibyte UTF-8
	// rune and produce an invalid string.
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

// bannerWorkers caps how many banner grabs run at once, so a large open-port
// set can't spawn thousands of simultaneous connections (one goroutine + socket
// per port), which starves file descriptors and trips connection rate limits.
const bannerWorkers = 64

// AddBanners fills the Banner field of each port on host with the raw product
// string (what CVE matching expects), in parallel but bounded by bannerWorkers.
// Ports that don't respond keep an empty banner.
func AddBanners(host string, ports []PortInfo, timeout time.Duration) {
	addBannersWith(grabBanner, host, ports, timeout)
}

// AddServiceBanners is AddBanners with the richer GrabBanner description (TLS
// version + cert CN, HTTP status), used for human-readable .
func AddServiceBanners(host string, ports []PortInfo, timeout time.Duration) {
	addBannersWith(GrabBanner, host, ports, timeout)
}

func addBannersWith(grab func(string, int, time.Duration) string, host string, ports []PortInfo, timeout time.Duration) {
	sem := make(chan struct{}, bannerWorkers)
	done := make(chan struct{}, len(ports))
	for i := range ports {
		go func(i int) {
			sem <- struct{}{}
			ports[i].Banner = grab(host, ports[i].Port, timeout)
			<-sem
			done <- struct{}{}
		}(i)
	}
	for range ports {
		<-done
	}
}
