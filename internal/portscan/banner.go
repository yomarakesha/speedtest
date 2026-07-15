package portscan

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// httpPorts are plaintext HTTP ports where we prompt with a HEAD request; most
// other services announce themselves on connect without prompting.
var httpPorts = map[int]bool{
	80: true, 8000: true, 8008: true, 8080: true, 8081: true,
	8888: true, 3000: true, 9000: true, 9090: true,
}

// tlsPorts are ports that speak TLS immediately; a plaintext banner grab would
// only capture binary handshake noise, so we skip them.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 993: true, 995: true, 8443: true,
}

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
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
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

// AddBanners fills the Banner field of each port on host, in parallel but
// bounded by bannerWorkers. Ports that don't respond keep an empty banner.
func AddBanners(host string, ports []PortInfo, timeout time.Duration) {
	sem := make(chan struct{}, bannerWorkers)
	done := make(chan struct{}, len(ports))
	for i := range ports {
		go func(i int) {
			sem <- struct{}{}
			ports[i].Banner = grabBanner(host, ports[i].Port, timeout)
			<-sem
			done <- struct{}{}
		}(i)
	}
	for range ports {
		<-done
	}
}
