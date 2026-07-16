package audit

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"speedtest/internal/util"
)

// AuditOptions selects which checks RunChecks performs and with what timeouts.
// The zero value is not valid; start from DefaultAuditOptions.
type AuditOptions struct {
	Timeout     time.Duration // TLS/HTTP/DNS/active per-check timeout
	PortTimeout time.Duration // port-scan connect timeout
	WithDNS     bool          // open-resolver / AXFR checks
	Active      bool          // intrusive checks (default creds, unauth services, CVE) — needs authorization
}

// DefaultAuditOptions returns the standard timeouts shared by the CLI and TUI so
// the same host grades identically in both. Only the passive checks are on.
func DefaultAuditOptions() AuditOptions {
	return AuditOptions{Timeout: 8 * time.Second, PortTimeout: time.Second}
}

// RunChecks runs the configured checks against target, calling emit (may be nil)
// for each finding as it is produced, and returns them all. TLS/HTTP failures
// are non-fatal — that check is skipped and onSkip (may be nil) is told why.
// This is the single orchestration point for both the CLI and the TUI.
func RunChecks(target string, opt AuditOptions, emit func(Finding), onSkip func(string)) []Finding {
	host := HostOnly(target)
	var findings []Finding
	add := func(fs []Finding) {
		for _, f := range fs {
			findings = append(findings, f)
			if emit != nil {
				emit(f)
			}
		}
	}

	// Discover every HTTP(S) service on the host (not just 443) and audit each:
	// headers, sensitive paths and — for https — TLS. This makes `audit <host>`
	// universal: apps on 8000/8080/9000/3000 are covered without naming the port.
	svcs := discoverWebServices(host, opt.PortTimeout)
	if len(svcs) == 0 && onSkip != nil {
		onSkip("HTTP/TLS пропущены: веб-сервисы не обнаружены")
	}
	for _, s := range svcs {
		add(auditWebService(host, s, opt.Timeout))
	}
	add(AuditPorts(host, opt.PortTimeout))
	add(AuditSMB(host, opt.PortTimeout))
	if opt.WithDNS {
		add(AuditDNS(host, opt.Timeout))
	}
	if opt.Active {
		add(AuditActive(host, opt.Timeout))
		add(AuditSNMP(host, opt.Timeout))
		add(AuditBannerCVEs(host, opt.Timeout))
	}
	return findings
}

// RunAudit is the CLI entry point for `speedtest audit <host>`: it runs every
// check (TLS, HTTP headers, risky ports) against one host and prints a single
// combined report.
func RunAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 8*time.Second, "таймаут TLS/HTTP")
	portTimeout := fs.Duration("port-timeout", time.Second, "таймаут скана портов")
	asJSON := fs.Bool("json", false, "вывод в формате JSON")
	export := fs.String("export", "", "формат отчёта: html | sarif")
	withDNS := fs.Bool("dns", false, "проверить DNS (открытый резолвер, AXFR)")
	compare := fs.Bool("compare", false, "сравнить с прошлым прогоном (что открылось/закрылось)")
	active := fs.Bool("i-have-authorization", false,
		"ВКЛЮЧИТЬ активные проверки (дефолт-креды, незащищённые сервисы, CVE) — только с разрешения владельца")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest audit <host> [--json]")
	}
	target := pos[0]

	// Machine/report output must be clean: suppress progress chatter.
	quiet := *asJSON || *export != ""
	if !quiet {
		fmt.Printf("Аудит %s: веб-сервисы (все порты), TLS, HTTP-заголовки, открытые порты ...\n", target)
		if *active {
			fmt.Println("  активные проверки (с вашей авторизацией): креды/сервисы/CVE ...")
		}
	}

	var onSkip func(string)
	if !quiet {
		onSkip = func(note string) { fmt.Printf("  (%s)\n", note) }
	}
	opt := AuditOptions{
		Timeout:     *timeout,
		PortTimeout: *portTimeout,
		WithDNS:     *withDNS,
		Active:      *active,
	}
	findings := RunChecks(target, opt, nil, onSkip)

	report := NewReport(target, findings)
	Record(report)

	// Drift detection: diff against the previous snapshot before overwriting it.
	if *compare && !quiet {
		prev, ok := LoadSnapshot(target)
		if !ok {
			fmt.Println("\nСравнить не с чем: это первый аудит цели (снимок сохранён).")
		} else {
			PrintDiff(DiffReports(prev, report))
		}
	}
	if err := SaveSnapshot(report); err != nil {
		fmt.Fprintf(os.Stderr, "audit: снимок не сохранён: %v\n", err)
	}

	switch *export {
	case "html":
		return ExportHTML(os.Stdout, report)
	case "sarif":
		return ExportSARIF(os.Stdout, report)
	case "":
		// fall through to normal output
	default:
		return fmt.Errorf("неизвестный формат экспорта %q (html|sarif)", *export)
	}
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
