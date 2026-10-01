// Package dnsbench compares DNS resolution speed across several resolvers
// (system + well-known public ones) over a set of domains.
package dnsbench

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"speedtest/internal/util"
)

// ServerSpec is one resolver to benchmark: Label is shown in output, Addr is
// its IP (empty Addr means "use the system resolver").
type ServerSpec struct {
	Label string
	Addr  string
}

// DefaultServers is the resolver set used when --servers is not given.
var DefaultServers = []ServerSpec{
	{"Системный", ""},
	{"Cloudflare", "1.1.1.1"},
	{"Google", "8.8.8.8"},
	{"Quad9", "9.9.9.9"},
	{"Яндекс", "77.88.8.8"},
	{"AdGuard", "94.140.14.14"},
	{"OpenDNS", "208.67.222.222"},
}

// DefaultDomains is the domain set used when --domains is not given.
var DefaultDomains = []string{"ya.ru", "google.com", "github.com", "wikipedia.org"}

// ServerResult is the outcome of benchmarking one resolver (--json).
type ServerResult struct {
	Server   string  `json:"server"`
	Addr     string  `json:"addr"`
	AvgMs    float64 `json:"avg_ms"`
	MinMs    float64 `json:"min_ms"`
	MaxMs    float64 `json:"max_ms"`
	Failures int     `json:"failures"`
	Total    int     `json:"total"`
}

// Bench resolves every domain against every server and returns one
// ServerResult per server, in the same order as servers.
func Bench(domains []string, servers []ServerSpec, timeout time.Duration) []ServerResult {
	out := make([]ServerResult, 0, len(servers))
	for _, srv := range servers {
		resolver := resolverFor(srv.Addr, timeout)
		var durations []time.Duration
		failures := 0
		for _, domain := range domains {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			start := time.Now()
			_, err := resolver.LookupHost(ctx, domain)
			dur := time.Since(start)
			cancel()
			if err != nil {
				failures++
				continue
			}
			durations = append(durations, dur)
		}
		avg, min, max := summarizeDurations(durations)
		out = append(out, ServerResult{
			Server: srv.Label, Addr: srv.Addr,
			AvgMs: avg, MinMs: min, MaxMs: max,
			Failures: failures, Total: len(domains),
		})
	}
	return out
}

// resolverFor builds a net.Resolver that queries addr:53, or the system
// resolver when addr is empty.
func resolverFor(addr string, timeout time.Duration) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(addr, "53"))
		},
	}
}

// summarizeDurations reduces a set of successful lookup durations to
// avg/min/max in milliseconds. An empty input yields all zeros.
func summarizeDurations(durations []time.Duration) (avg, min, max float64) {
	if len(durations) == 0 {
		return 0, 0, 0
	}
	min = durations[0].Seconds() * 1000
	max = min
	var sum float64
	for _, d := range durations {
		ms := d.Seconds() * 1000
		sum += ms
		if ms < min {
			min = ms
		}
		if ms > max {
			max = ms
		}
	}
	return sum / float64(len(durations)), min, max
}

// parseServers parses a comma-separated --servers flag value, each entry
// either "label=addr" or a bare "addr" (used as its own label).
func parseServers(s string) []ServerSpec {
	if strings.TrimSpace(s) == "" {
		return DefaultServers
	}
	var out []ServerSpec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if label, addr, ok := strings.Cut(part, "="); ok {
			out = append(out, ServerSpec{Label: label, Addr: addr})
		} else {
			out = append(out, ServerSpec{Label: part, Addr: part})
		}
	}
	return out
}

// parseDomains parses a comma-separated --domains flag value.
func parseDomains(s string) []string {
	if strings.TrimSpace(s) == "" {
		return DefaultDomains
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// RunDNS is the CLI entry point for `speedtest dns`.
func RunDNS(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	domainsFlag := fs.String("domains", "", "comma-separated domains (default: a small built-in set)")
	serversFlag := fs.String("servers", "", "comma-separated label=addr or addr (default: system + well-known public resolvers)")
	timeout := fs.Duration("timeout", 3*time.Second, "per-lookup timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	if _, err := util.ParseFlags(fs, args); err != nil {
		return err
	}

	domains := parseDomains(*domainsFlag)
	servers := parseServers(*serversFlag)

	results := Bench(domains, servers, *timeout)

	if *asJSON {
		b, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Сравнение DNS-резолверов по %d доменам: %s\n\n", len(domains), strings.Join(domains, ", "))
	fmt.Printf("%-14s %-16s %8s %8s %8s %8s\n", "Резолвер", "Адрес", "сред.мс", "мин.мс", "макс.мс", "ошибки")
	for _, r := range results {
		addr := r.Addr
		if addr == "" {
			addr = "(система)"
		}
		fails := fmt.Sprintf("%d/%d", r.Failures, r.Total)
		if r.Failures == r.Total {
			fmt.Printf("%-14s %-16s %8s %8s %8s %8s\n", r.Server, addr, "—", "—", "—", fails)
			continue
		}
		fmt.Printf("%-14s %-16s %8.1f %8.1f %8.1f %8s\n", r.Server, addr, r.AvgMs, r.MinMs, r.MaxMs, fails)
	}
	return nil
}
