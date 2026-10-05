// Package tlsaudit performs a deeper TLS assessment than tlsinfo: it enumerates
// which TLS protocol versions a server accepts (flagging obsolete TLS 1.0/1.1),
// probes for weak/insecure cipher suites, and inspects the leaf certificate for
// expiry, self-signing, and weak (SHA-1) signatures — then grades the result A–F.
package tlsaudit

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"speedtest/internal/report"
	"speedtest/internal/util"
)

// DefaultPort is used when the host has no explicit :port.
const DefaultPort = 443

// probeVersions are the TLS versions enumerated, newest first.
var probeVersions = []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

// VersionResult records whether one TLS version is accepted.
type VersionResult struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Weak      bool   `json:"weak"`
}

// CertInfo summarizes the leaf certificate's security-relevant fields.
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotAfter      time.Time `json:"not_after"`
	Expired       bool      `json:"expired"`
	SelfSigned    bool      `json:"self_signed"`
	SignatureAlgo string    `json:"signature_algo"`
	WeakSignature bool      `json:"weak_signature"`
}

// Result is the full deep-TLS audit of one host.
type Result struct {
	Host        string          `json:"host"`
	Versions    []VersionResult `json:"versions"`
	WeakCiphers []string        `json:"weak_ciphers,omitempty"`
	Cert        CertInfo        `json:"cert"`
	CertOK      bool            `json:"cert_ok"`
	CertError   string          `json:"cert_error,omitempty"`
	Grade       string          `json:"grade"`
}

// sanitize strips control characters (including the C1 range) so a hostile
// certificate field cannot inject terminal escape sequences when printed.
func sanitize(s string) string { return util.SanitizeLine(s) }

// versionWeak reports whether a TLS version is considered obsolete.
func versionWeak(v uint16) bool {
	return v == tls.VersionTLS10 || v == tls.VersionTLS11
}

// weakSignature reports whether a certificate signature algorithm is weak.
func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// rate grades a Result. It is pure: F on expired/weak-signature, else demote by
// obsolete versions, weak ciphers and self-signing. When the certificate could
// not be retrieved (certOK=false) the grade is penalized rather than treating an
// absent cert as clean — fail closed, not open.
func rate(versions []VersionResult, weakCiphers []string, cert CertInfo, certOK bool) string {
	if certOK && (cert.Expired || cert.WeakSignature) {
		return "F"
	}
	score := 100
	for _, v := range versions {
		if v.Supported && v.Weak {
			score -= 25
		}
	}
	score -= 20 * len(weakCiphers)
	if !certOK {
		score -= 40 // cannot vouch for a cert we could not read
	} else if cert.SelfSigned {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// NormalizeHost returns host:port, defaulting the port to 443.
func NormalizeHost(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, fmt.Sprint(DefaultPort))
	}
	return host
}

// Audit assesses the TLS configuration of hostport.
func Audit(hostport string, timeout time.Duration) (Result, error) {
	hostport = NormalizeHost(hostport)
	host, _, _ := net.SplitHostPort(hostport)
	res := Result{Host: hostport}

	// Enumerate protocol versions.
	anySupported := false
	for _, v := range probeVersions {
		ok := dialVersion(hostport, host, v, timeout)
		if ok {
			anySupported = true
		}
		res.Versions = append(res.Versions, VersionResult{
			Name:      tls.VersionName(v),
			Supported: ok,
			Weak:      versionWeak(v),
		})
	}
	if !anySupported {
		return Result{}, fmt.Errorf("не удалось установить TLS-соединение с %s", hostport)
	}

	// Probe weak/insecure cipher suites.
	for _, cs := range tls.InsecureCipherSuites() {
		if dialCipher(hostport, host, cs.ID, timeout) {
			res.WeakCiphers = append(res.WeakCiphers, cs.Name)
		}
	}

	// Inspect the leaf certificate. A fetch failure must not be graded as a
	// clean cert, so record the error and let rate() penalize the unknown.
	if cert, err := leafCert(hostport, host, timeout); err == nil {
		res.Cert = certInfo(cert, host)
		res.CertOK = true
	} else {
		res.CertError = sanitize(err.Error())
	}

	res.Grade = rate(res.Versions, res.WeakCiphers, res.Cert, res.CertOK)
	return res, nil
}

// dialVersion reports whether the server completes a handshake pinned to version v.
func dialVersion(addr, host string, v uint16, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // version probe, not a trusting client
		ServerName:         host,
		MinVersion:         v,
		MaxVersion:         v,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dialCipher reports whether the server accepts a handshake offering only cipher
// id. Limitation: Go's tls client can only offer the suites it still implements,
// so a server that accepts a suite Go has dropped entirely cannot be detected
// here — a clean weak-cipher result is a lower bound, not a guarantee.
func dialCipher(addr, host string, id uint16, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // cipher probe, not a trusting client
		ServerName:         host,
		MaxVersion:         tls.VersionTLS12, // insecure suites are pre-1.3
		CipherSuites:       []uint16{id},
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// leafCert returns the server's leaf certificate.
func leafCert(addr, host string, timeout time.Duration) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // cert inspection, not a trusting client
		ServerName:         host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("нет сертификата")
	}
	return certs[0], nil
}

// certInfo extracts the security-relevant certificate fields.
func certInfo(cert *x509.Certificate, host string) CertInfo {
	ci := CertInfo{
		Subject:       sanitize(cert.Subject.String()),
		Issuer:        sanitize(cert.Issuer.String()),
		NotAfter:      cert.NotAfter,
		Expired:       time.Now().After(cert.NotAfter),
		SignatureAlgo: sanitize(cert.SignatureAlgorithm.String()),
		WeakSignature: weakSignature(cert.SignatureAlgorithm),
	}
	// Self-signed: issuer equals subject and it fails to chain to a trusted root.
	if cert.Issuer.String() == cert.Subject.String() {
		roots, _ := x509.SystemCertPool()
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			ci.SelfSigned = true
		}
	}
	return ci
}

// RunTLSAudit is the CLI entry point for `speedtest tlsaudit <host[:port]>`.
func RunTLSAudit(args []string) error {
	fs := flag.NewFlagSet("tlsaudit", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 6*time.Second, "per-probe timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	wazuh := fs.Bool("wazuh", false, "emit finding to the Wazuh report log")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest tlsaudit <host[:port]>")
	}

	res, err := Audit(pos[0], *timeout)
	if err != nil {
		return err
	}

	if *wazuh {
		sev := report.SeverityInfo
		switch res.Grade {
		case "C":
			sev = report.SeverityLow
		case "D":
			sev = report.SeverityMedium
		case "F":
			sev = report.SeverityHigh
		}
		_ = report.Emit(report.Event{
			Tool:     "tlsaudit",
			Target:   res.Host,
			Severity: sev,
			Summary:  fmt.Sprintf("TLS-аудит: оценка %s", res.Grade),
			Data: map[string]any{
				"grade":        res.Grade,
				"weak_ciphers": res.WeakCiphers,
				"expired":      res.Cert.Expired,
				"self_signed":  res.Cert.SelfSigned,
			},
		})
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Глубокий TLS-аудит %s\n", res.Host)
	fmt.Println("  Версии протокола:")
	for _, v := range res.Versions {
		mark := "—"
		if v.Supported {
			mark = "✓"
			if v.Weak {
				mark = "⚠"
			}
		}
		fmt.Printf("    %s %s%s\n", mark, v.Name, weakTag(v))
	}
	if len(res.WeakCiphers) > 0 {
		fmt.Printf("  ⚠ Слабые шифры: %s\n", strings.Join(res.WeakCiphers, ", "))
	} else {
		fmt.Println("  ✓ Слабые шифры не приняты")
	}
	if !res.CertOK {
		fmt.Printf("  ⚠ Сертификат не получен: %s\n", res.CertError)
		fmt.Printf("\n  Оценка: %s\n", res.Grade)
		return nil
	}
	fmt.Printf("  Сертификат: %s\n", res.Cert.Subject)
	fmt.Printf("    Издатель:  %s\n", res.Cert.Issuer)
	fmt.Printf("    Действует до: %s\n", res.Cert.NotAfter.Format("2006-01-02"))
	if res.Cert.Expired {
		fmt.Println("    ⚠ срок действия истёк")
	}
	if res.Cert.SelfSigned {
		fmt.Println("    ⚠ самоподписанный")
	}
	fmt.Printf("    Подпись:   %s\n", res.Cert.SignatureAlgo)
	if res.Cert.WeakSignature {
		fmt.Println("    ⚠ слабый алгоритм подписи")
	}
	fmt.Printf("\n  Оценка: %s\n", res.Grade)
	return nil
}

func weakTag(v VersionResult) string {
	if v.Supported && v.Weak {
		return " (устаревший)"
	}
	return ""
}
