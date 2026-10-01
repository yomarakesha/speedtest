// Package tlsinfo inspects the TLS certificate a server presents: issuer,
// subject, validity window, negotiated TLS version/cipher, SAN names and
// handshake time. The connection always completes (certificate validation is
// skipped during the handshake) so even an expired or self-signed cert can be
// inspected; validity is then checked separately and reported as a field,
// never silently trusted.
package tlsinfo

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"speedtest/internal/util"
)

// DefaultPort is used when the host has no explicit :port.
const DefaultPort = 443

// Result is the outcome of a certificate inspection (used for --json).
type Result struct {
	Host        string    `json:"host"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Expired     bool      `json:"expired"`
	Version     string    `json:"tls_version"`
	CipherSuite string    `json:"cipher_suite"`
	SANs        []string  `json:"sans"`
	HandshakeMs float64   `json:"handshake_ms"`
	VerifyError string    `json:"verify_error,omitempty"`
}

// NormalizeHost returns host:port, defaulting the port to DefaultPort when
// host has none.
func NormalizeHost(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, fmt.Sprint(DefaultPort))
	}
	return host
}

// Inspect dials hostport over TLS and reports the presented certificate.
func Inspect(hostport string, timeout time.Duration) (Result, error) {
	hostport = NormalizeHost(hostport)
	host, _, _ := net.SplitHostPort(hostport)

	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", hostport, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: this is a cert inspector, not a trusting client
		ServerName:         host,
	})
	if err != nil {
		return Result{}, fmt.Errorf("TLS-подключение: %w", err)
	}
	defer conn.Close()
	handshake := time.Since(start)

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Result{}, fmt.Errorf("сервер не предъявил сертификат")
	}
	leaf := state.PeerCertificates[0]

	res := Result{
		Host:        hostport,
		Issuer:      leaf.Issuer.String(),
		Subject:     leaf.Subject.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		Expired:     time.Now().After(leaf.NotAfter),
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SANs:        leaf.DNSNames,
		HandshakeMs: handshake.Seconds() * 1000,
	}

	if err := verify(state.PeerCertificates, host); err != nil {
		res.VerifyError = err.Error()
	}
	return res, nil
}

// verify checks the full chain against the system trust store and host name.
func verify(certs []*x509.Certificate, host string) error {
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	})
	return err
}

// RunTLS is the CLI entry point for `speedtest tls <host[:port]>`.
func RunTLS(args []string) error {
	fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "handshake timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest tls <host[:port]>")
	}

	res, err := Inspect(pos[0], *timeout)
	if err != nil {
		return err
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Сертификат %s\n", res.Host)
	fmt.Printf("  Издатель:    %s\n", res.Issuer)
	fmt.Printf("  Субъект:     %s\n", res.Subject)
	fmt.Printf("  Действителен: %s — %s\n", res.NotBefore.Format("2006-01-02"), res.NotAfter.Format("2006-01-02"))
	if res.Expired {
		fmt.Println("  ⚠ Срок действия сертификата истёк")
	}
	fmt.Printf("  Версия TLS:  %s\n", res.Version)
	fmt.Printf("  Шифр:        %s\n", res.CipherSuite)
	if len(res.SANs) > 0 {
		fmt.Printf("  SAN-имена:   %s\n", strings.Join(res.SANs, ", "))
	}
	fmt.Printf("  Рукопожатие: %.1f мс\n", res.HandshakeMs)
	if res.VerifyError != "" {
		fmt.Printf("  ⚠ Проверка цепочки доверия не пройдена: %s\n", res.VerifyError)
	} else {
		fmt.Println("  Цепочка доверия: действительна")
	}
	return nil
}
