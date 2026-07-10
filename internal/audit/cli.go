package audit

import (
	"flag"
	"fmt"
	"time"

	"speedtest/internal/util"
)

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
