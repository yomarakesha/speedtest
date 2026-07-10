package audit

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"speedtest/internal/util"
)

// RunAudit is the CLI entry point for `speedtest audit <host>`: it runs every
// check (TLS, HTTP headers, risky ports) against one host and prints a single
// combined report.
func RunAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 8*time.Second, "таймаут TLS/HTTP")
	portTimeout := fs.Duration("port-timeout", time.Second, "таймаут скана портов")
	asJSON := fs.Bool("json", false, "вывод в формате JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest audit <host> [--json]")
	}
	target := pos[0]
	host := HostOnly(target)

	if !*asJSON {
		fmt.Printf("Аудит %s: TLS, HTTP-заголовки, открытые порты ...\n", target)
	}

	var findings []Finding
	if fs, err := AuditTLS(target, 443, *timeout); err == nil {
		findings = append(findings, fs...)
	} else if !*asJSON {
		fmt.Printf("  (TLS пропущен: %v)\n", err)
	}
	if fs, err := AuditHTTP(target, *timeout); err == nil {
		findings = append(findings, fs...)
	} else if !*asJSON {
		fmt.Printf("  (HTTP пропущен: %v)\n", err)
	}
	findings = append(findings, AuditPorts(host, *portTimeout)...)

	report := NewReport(target, findings)
	if *asJSON {
		return PrintJSON(report)
	}
	PrintReport(report)
	return nil
}

// HostOnly strips a scheme and port from a target, leaving the bare host for
// the port scan.
func HostOnly(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		target = target[i+3:]
	}
	if i := strings.IndexByte(target, '/'); i >= 0 {
		target = target[:i]
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

// RunTLSAudit is the CLI entry point for `speedtest tlsaudit <host[:443]>`.
func RunTLSAudit(args []string) error {
	fs := flag.NewFlagSet("tlsaudit", flag.ContinueOnError)
	port := fs.Int("port", 443, "порт TLS, если не указан в хосте")
	timeout := fs.Duration("timeout", 8*time.Second, "таймаут соединения")
	asJSON := fs.Bool("json", false, "вывод в формате JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest tlsaudit <host[:443]> [--json]")
	}
	target := pos[0]

	if !*asJSON {
		fmt.Printf("Проверяю TLS %s ...\n", target)
	}
	findings, err := AuditTLS(target, *port, *timeout)
	if err != nil {
		return err
	}
	report := NewReport(target, findings)
	if *asJSON {
		return PrintJSON(report)
	}
	PrintReport(report)
	return nil
}

// RunHTTPAudit is the CLI entry point for `speedtest httpaudit <url>`.
func RunHTTPAudit(args []string) error {
	fs := flag.NewFlagSet("httpaudit", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "таймаут запроса")
	asJSON := fs.Bool("json", false, "вывод в формате JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest httpaudit <url> [--json]")
	}
	target := pos[0]

	if !*asJSON {
		fmt.Printf("Проверяю HTTP-заголовки %s ...\n", target)
	}
	findings, err := AuditHTTP(target, *timeout)
	if err != nil {
		return err
	}
	report := NewReport(target, findings)
	if *asJSON {
		return PrintJSON(report)
	}
	PrintReport(report)
	return nil
}
