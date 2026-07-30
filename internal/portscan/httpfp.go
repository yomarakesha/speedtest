package portscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// WebInfo is a lightweight fingerprint of an HTTP service on one open port: the
// response status, the redirect it points to, the page title, and the software
// guessed from headers and body. It is the local-only equivalent of what
// whatweb/httpx report — no external service, no wordlist.
type WebInfo struct {
	Port     int      `json:"port"`
	Scheme   string   `json:"scheme"`
	Status   int      `json:"status"`
	Title    string   `json:"title,omitempty"`
	Server   string   `json:"server,omitempty"`
	Redirect string   `json:"redirect,omitempty"`
	Tech     []string `json:"tech,omitempty"`
}

// webProbePorts are the ports fingerprintWeb tries as HTTP. httpsPorts among
// them are spoken over TLS; the rest as plaintext HTTP.
var httpsPorts = map[int]bool{
	443: true, 8443: true, 9443: true, 4443: true, 10443: true, 8843: true,
}

// isWebPort reports whether a port is worth an HTTP fingerprint attempt.
func isWebPort(p int) bool {
	if httpsPorts[p] || httpPorts[p] {
		return true
	}
	switch p {
	case 443, 80, 280, 591, 593, 2480, 4567, 5000, 5104, 5800, 7001, 8000,
		8008, 8080, 8081, 8088, 8090, 8180, 8280, 8880, 9000, 9080, 9090, 3000:
		return true
	}
	return false
}

// FingerprintWeb probes each open web port on host and returns what each HTTP
// service reveals about itself. host is an address; serverName is the original
// name (sent as SNI and Host so name-based virtual hosts answer correctly).
func FingerprintWeb(ctx context.Context, host, serverName string, ports []int, timeout time.Duration) []WebInfo {
	var targets []int
	for _, p := range ports {
		if isWebPort(p) {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	var mu sync.Mutex
	var out []WebInfo
	var wg sync.WaitGroup
	for _, p := range targets {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if info, ok := fingerprintPort(ctx, host, serverName, port, timeout); ok {
				mu.Lock()
				out = append(out, info)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// fingerprintPort fetches "/" on one port and extracts its fingerprint. It does
// not follow redirects — a 301 to HTTPS is itself a useful signal — and reads a
// bounded body so a large page can't stall the scan.
func fingerprintPort(ctx context.Context, host, serverName string, port int, timeout time.Duration) (WebInfo, bool) {
	scheme := "http"
	if httpsPorts[port] {
		scheme = "https"
	}
	info := WebInfo{Port: port, Scheme: scheme}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// Reading the fingerprint, not trusting the cert: an expired or
			// self-signed cert must not stop us from identifying the service.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
		},
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, false
	}
	if serverName != "" {
		req.Host = serverName
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; speedtest-scan/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return info, false
	}
	defer resp.Body.Close()

	info.Status = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	if loc := resp.Header.Get("Location"); loc != "" {
		info.Redirect = loc
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	info.Title = pageTitle(body)
	info.Tech = detectTech(resp.Header, string(body))
	return info, true
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var wsRe = regexp.MustCompile(`\s+`)

// pageTitle extracts and tidies the <title> text of an HTML body, or "".
func pageTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := wsRe.ReplaceAllString(strings.TrimSpace(string(m[1])), " ")
	if len(title) > 120 {
		title = title[:120] + "…"
	}
	return title
}

// techSignature identifies a technology by a header or a body marker.
type techSignature struct {
	name   string
	header string // header name to inspect; empty => body match
	needle string // case-insensitive substring that confirms the tech
}

// techSignatures are high-signal markers for common web software. Ordered
// roughly server → framework → CMS → frontend; each is a substring that only
// that technology emits.
var techSignatures = []techSignature{
	{"nginx", "Server", "nginx"},
	{"Apache", "Server", "apache"},
	{"IIS", "Server", "microsoft-iis"},
	{"LiteSpeed", "Server", "litespeed"},
	{"Caddy", "Server", "caddy"},
	{"Google Web Server", "Server", "gws"},
	{"Cloudflare", "Server", "cloudflare"},
	{"Envoy", "Server", "envoy"},
	{"Kestrel", "Server", "kestrel"},
	{"Gunicorn", "Server", "gunicorn"},
	{"Werkzeug", "Server", "werkzeug"},
	{"Jetty", "Server", "jetty"},
	{"Tomcat", "Server", "tomcat"},
	{"Cowboy", "Server", "cowboy"},
	{"PHP", "X-Powered-By", "php"},
	{"ASP.NET", "X-Powered-By", "asp.net"},
	{"ASP.NET", "X-AspNet-Version", ""},
	{"Express", "X-Powered-By", "express"},
	{"Next.js", "X-Powered-By", "next.js"},
	{"Next.js", "", "/_next/static"},
	{"Nuxt", "", "__nuxt"},
	{"Django", "", "csrfmiddlewaretoken"},
	{"Laravel", "Set-Cookie", "laravel_session"},
	{"Ruby on Rails", "Set-Cookie", "_rails"},
	{"WordPress", "", "/wp-content/"},
	{"WordPress", "", "/wp-includes/"},
	{"Drupal", "X-Generator", "drupal"},
	{"Drupal", "", "sites/all/"},
	{"Joomla", "", "/media/jui/"},
	{"Magento", "", "mage/cookies"},
	{"Shopify", "", "cdn.shopify.com"},
	{"React", "", "data-reactroot"},
	{"Vue.js", "", "data-v-app"},
	{"Angular", "", "ng-version"},
	{"jQuery", "", "jquery"},
	{"Bootstrap", "", "bootstrap"},
	{"Grafana", "", "grafana"},
	{"Kibana", "", "kbn-name"},
	{"Prometheus", "", "prometheus"},
	{"Jenkins", "X-Jenkins", ""},
	{"GitLab", "", "gitlab"},
	{"phpMyAdmin", "", "phpmyadmin"},
	{"Kubernetes Dashboard", "", "kubernetes-dashboard"},
	{"Swagger UI", "", "swagger-ui"},
	{"Varnish", "Via", "varnish"},
	{"HSTS", "Strict-Transport-Security", ""},
}

// detectTech returns the distinct technologies inferred from the response
// headers and body, in a stable order. A signature with an empty needle fires
// on the mere presence of its header.
func detectTech(header http.Header, body string) []string {
	lowerBody := strings.ToLower(body)
	seen := map[string]bool{}
	var out []string
	for _, sig := range techSignatures {
		if matchSignature(sig, header, lowerBody) && !seen[sig.name] {
			seen[sig.name] = true
			out = append(out, sig.name)
		}
	}
	return out
}

// matchSignature reports whether one signature is present.
func matchSignature(sig techSignature, header http.Header, lowerBody string) bool {
	if sig.header != "" {
		v := strings.ToLower(header.Get(sig.header))
		if v == "" {
			return false
		}
		return sig.needle == "" || strings.Contains(v, sig.needle)
	}
	return sig.needle != "" && strings.Contains(lowerBody, sig.needle)
}
