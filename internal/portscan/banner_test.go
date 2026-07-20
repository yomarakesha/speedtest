package portscan

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startGreetServer listens on localhost and writes greeting to each client on
// connect, returning the chosen port.
func startGreetServer(t *testing.T, greeting string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(greeting))
			c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return port
}

func TestGrabBannerGreeting(t *testing.T) {
	port := startGreetServer(t, "SSH-2.0-OpenSSH_9.6\r\nextra\r\n")
	got := grabBanner("127.0.0.1", port, time.Second)
	if got != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("grabBanner = %q, want SSH greeting", got)
	}
}

func TestGrabBannerHTTPServerHeader(t *testing.T) {
	// Serve an HTTP response with a Server header on an HTTP-classified port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n') // consume request line
			c.Write([]byte("HTTP/1.0 200 OK\r\nServer: nginx/1.25.3\r\n\r\n"))
			c.Close()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	httpPorts[port] = true // classify this ephemeral port as HTTP for the test
	t.Cleanup(func() { delete(httpPorts, port) })

	got := grabBanner("127.0.0.1", port, time.Second)
	if got != "nginx/1.25.3" {
		t.Errorf("grabBanner = %q, want nginx Server header", got)
	}
}

func TestGrabBannerSkipsTLSPorts(t *testing.T) {
	if got := grabBanner("127.0.0.1", 443, 200*time.Millisecond); got != "" {
		t.Errorf("expected empty banner for TLS port, got %q", got)
	}
}

func TestSanitizeBanner(t *testing.T) {
	if got := sanitizeBanner("  hi\x00\x07there \r\n"); got != "hithere" {
		t.Errorf("sanitizeBanner = %q", got)
	}
	long := strings.Repeat("a", 200)
	if got := sanitizeBanner(long); len([]rune(got)) != 81 {
		t.Errorf("sanitizeBanner did not cap length: %d runes", len([]rune(got)))
	}
}
