// Package timing breaks a single HTTP request down into DNS lookup, TCP
// connect, TLS handshake, time-to-first-byte and total stages, using
// net/http/httptrace hooks.
package timing

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"speedtest/internal/util"
)

// Result is the per-stage timing breakdown of one HTTP request (--json).
type Result struct {
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	DNSMs      float64 `json:"dns_ms"`
	ConnectMs  float64 `json:"connect_ms"`
	TLSMs      float64 `json:"tls_ms"`
	TTFBMs     float64 `json:"ttfb_ms"`
	TotalMs    float64 `json:"total_ms"`
}

// normalizeURL prepends http:// when the argument is a bare host or ip[:port].
func normalizeURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "http://" + s
}

// Measure performs one GET request against url and times its stages. It does
// not follow redirects, so the breakdown always describes a single round trip.
func Measure(rawURL string, timeout time.Duration) (Result, error) {
	url := normalizeURL(rawURL)

	var dnsStart, dnsDone, connectStart, connectDone, tlsStart, tlsDone, firstByte time.Time

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "speedtest/1.0")

	ct := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:         func(string, string) { connectStart = time.Now() },
		ConnectDone:          func(string, string, error) { connectDone = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), ct))

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	total := time.Since(start)

	res := Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		TotalMs:    total.Seconds() * 1000,
	}
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		res.DNSMs = dnsDone.Sub(dnsStart).Seconds() * 1000
	}
	if !connectStart.IsZero() && !connectDone.IsZero() {
		res.ConnectMs = connectDone.Sub(connectStart).Seconds() * 1000
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		res.TLSMs = tlsDone.Sub(tlsStart).Seconds() * 1000
	}
	if !firstByte.IsZero() {
		res.TTFBMs = firstByte.Sub(start).Seconds() * 1000
	}
	return res, nil
}

// FormatLines renders a Result as human-readable Russian lines, in the order
// the stages occur.
func FormatLines(r Result) []string {
	lines := []string{
		fmt.Sprintf("Статус:        %d", r.StatusCode),
		fmt.Sprintf("DNS:           %.1f мс", r.DNSMs),
		fmt.Sprintf("TCP-подключение: %.1f мс", r.ConnectMs),
	}
	if r.TLSMs > 0 {
		lines = append(lines, fmt.Sprintf("TLS handshake: %.1f мс", r.TLSMs))
	} else {
		lines = append(lines, "TLS handshake: — (без TLS)")
	}
	lines = append(lines,
		fmt.Sprintf("До первого байта (TTFB): %.1f мс", r.TTFBMs),
		fmt.Sprintf("Итого:         %.1f мс", r.TotalMs),
	)
	return lines
}

// RunTiming is the CLI entry point for `speedtest timing <url>`.
func RunTiming(args []string) error {
	fs := flag.NewFlagSet("timing", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest timing <url>")
	}

	res, err := Measure(pos[0], *timeout)
	if err != nil {
		return err
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Разбивка времени запроса к %s\n\n", res.URL)
	for _, l := range FormatLines(res) {
		fmt.Println("  " + l)
	}
	return nil
}
