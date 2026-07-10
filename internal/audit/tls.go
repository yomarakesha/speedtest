package audit

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// certExpiryWarn is how soon a certificate must expire to raise a warning.
const certExpiryWarn = 30 * 24 * time.Hour

// tlsVersions lists the protocol versions probed one-by-one, weakest first.
var tlsVersions = []struct {
	id   uint16
	name string
	weak bool // considered insecure/deprecated
}{
	{tls.VersionTLS10, "TLS 1.0", true},
	{tls.VersionTLS11, "TLS 1.1", true},
	{tls.VersionTLS12, "TLS 1.2", false},
	{tls.VersionTLS13, "TLS 1.3", false},
}

// AuditTLS connects to host:port, inspects the certificate and probes which
// protocol versions the server accepts, returning findings. host may include a
// port; if not, defaultPort is used.
func AuditTLS(host string, defaultPort int, timeout time.Duration) ([]Finding, error) {
	hostname, addr := splitHostPort(host, defaultPort)

	// Baseline handshake (any version) to fetch the certificate chain.
	state, err := handshake(addr, hostname, 0, timeout)
	if err != nil {
		return nil, fmt.Errorf("не удалось установить TLS-соединение с %s: %w", addr, err)
	}

	var findings []Finding
	findings = append(findings, certFindings(state, hostname)...)
	findings = append(findings, versionFindings(addr, hostname, timeout)...)
	return findings, nil
}

// handshake performs a TLS handshake and returns the negotiated state. If
// version is non-zero the handshake is pinned to exactly that version.
func handshake(addr, serverName string, version uint16, timeout time.Duration) (tls.ConnectionState, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we assess trust ourselves; don't abort on it
	}
	if version != 0 {
		cfg.MinVersion, cfg.MaxVersion = version, version
	} else {
		// Baseline: accept the widest range so we can still fetch the cert
		// from servers that only speak deprecated versions.
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS13
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

// certFindings inspects the leaf certificate for expiry, hostname mismatch and
// trust problems.
func certFindings(state tls.ConnectionState, hostname string) []Finding {
	if len(state.PeerCertificates) == 0 {
		return []Finding{{
			Check: "tls.no_certificate", Severity: High,
			Title: "Сертификат не предоставлен",
		}}
	}
	leaf := state.PeerCertificates[0]
	var out []Finding
	now := time.Now()

	switch {
	case now.After(leaf.NotAfter):
		out = append(out, Finding{
			Check: "tls.cert_expired", Severity: High,
			Title:    "Сертификат просрочен",
			Detail:   "истёк " + leaf.NotAfter.Format("2006-01-02"),
			Evidence: leaf.Subject.CommonName,
		})
	case leaf.NotAfter.Sub(now) < certExpiryWarn:
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		out = append(out, Finding{
			Check: "tls.cert_expiring", Severity: Medium,
			Title:  "Сертификат скоро истекает",
			Detail: fmt.Sprintf("осталось %d дн. (до %s)", days, leaf.NotAfter.Format("2006-01-02")),
		})
	}
	if now.Before(leaf.NotBefore) {
		out = append(out, Finding{
			Check: "tls.cert_not_yet_valid", Severity: Medium,
			Title:  "Сертификат ещё не действителен",
			Detail: "действует с " + leaf.NotBefore.Format("2006-01-02"),
		})
	}

	// Hostname verification against the leaf's SANs.
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			out = append(out, Finding{
				Check: "tls.hostname_mismatch", Severity: High,
				Title:    "Имя хоста не совпадает с сертификатом",
				Detail:   err.Error(),
				Evidence: strings.Join(leaf.DNSNames, ", "),
			})
		}
	}

	// Chain trust against the system roots.
	if trust := verifyTrust(state, hostname); trust != nil {
		out = append(out, *trust)
	}

	// Weak signature algorithms.
	if isWeakSignature(leaf.SignatureAlgorithm) {
		out = append(out, Finding{
			Check: "tls.weak_signature", Severity: Medium,
			Title:  "Слабый алгоритм подписи сертификата",
			Detail: leaf.SignatureAlgorithm.String(),
		})
	}
	return out
}

// verifyTrust checks the presented chain against the host's trust store and
// returns a Finding when it does not verify (self-signed, unknown CA, etc.).
func verifyTrust(state tls.ConnectionState, hostname string) *Finding {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil // can't assess without a trust store; skip silently
	}
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: inter,
	})
	if err == nil {
		return nil
	}
	sev := Medium
	title := "Цепочка сертификата не проверена"
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		title = "Недоверенный/самоподписанный сертификат"
	}
	return &Finding{
		Check: "tls.untrusted_chain", Severity: sev,
		Title: title, Detail: err.Error(),
	}
}

// versionFindings probes each protocol version and flags deprecated ones the
// server still accepts.
func versionFindings(addr, hostname string, timeout time.Duration) []Finding {
	var out []Finding
	var supported []string
	for _, v := range tlsVersions {
		st, err := handshake(addr, hostname, v.id, timeout)
		if err != nil || st.Version != v.id {
			continue
		}
		supported = append(supported, v.name)
		if v.weak {
			out = append(out, Finding{
				Check: "tls.weak_protocol", Severity: High,
				Title:  "Устаревший протокол включён",
				Detail: v.name + " небезопасен и должен быть отключён",
			})
		}
	}
	if len(supported) > 0 {
		out = append(out, Finding{
			Check: "tls.protocols", Severity: Info,
			Title:  "Поддерживаемые протоколы",
			Detail: strings.Join(supported, ", "),
		})
	}
	return out
}

// isWeakSignature reports whether a certificate signature algorithm relies on a
// broken hash (MD5 or SHA-1).
func isWeakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// splitHostPort separates a "host[:port]" target, applying defaultPort when the
// port is absent. It returns the bare hostname (for SNI/verification) and the
// dial address.
func splitHostPort(target string, defaultPort int) (hostname, addr string) {
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, net.JoinHostPort(h, p)
	}
	return target, net.JoinHostPort(target, fmt.Sprint(defaultPort))
}
