package tlsaudit

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestVersionWeak(t *testing.T) {
	if !versionWeak(tls.VersionTLS10) || !versionWeak(tls.VersionTLS11) {
		t.Error("TLS 1.0/1.1 must be weak")
	}
	if versionWeak(tls.VersionTLS12) || versionWeak(tls.VersionTLS13) {
		t.Error("TLS 1.2/1.3 must not be weak")
	}
}

func TestWeakSignature(t *testing.T) {
	for _, a := range []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.MD5WithRSA, x509.ECDSAWithSHA1} {
		if !weakSignature(a) {
			t.Errorf("%v should be weak", a)
		}
	}
	for _, a := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.ECDSAWithSHA256} {
		if weakSignature(a) {
			t.Errorf("%v should not be weak", a)
		}
	}
}

func vers(modern, weak bool) []VersionResult {
	return []VersionResult{
		{Name: "1.3", Supported: modern, Weak: false},
		{Name: "1.0", Supported: weak, Weak: true},
	}
}

func TestRate(t *testing.T) {
	good := CertInfo{NotAfter: time.Now().Add(time.Hour)}
	cases := []struct {
		name     string
		versions []VersionResult
		ciphers  []string
		cert     CertInfo
		certOK   bool
		want     string
	}{
		{"clean", vers(true, false), nil, good, true, "A"},
		{"obsolete TLS1.0", vers(true, true), nil, good, true, "B"},
		{"weak cipher", vers(true, false), []string{"RC4"}, good, true, "B"},
		{"self-signed", vers(true, false), nil, CertInfo{NotAfter: time.Now().Add(time.Hour), SelfSigned: true}, true, "B"},
		{"expired", vers(true, false), nil, CertInfo{Expired: true}, true, "F"},
		{"weak signature", vers(true, false), nil, CertInfo{NotAfter: time.Now().Add(time.Hour), WeakSignature: true}, true, "F"},
		{"obsolete + 2 weak ciphers", vers(true, true), []string{"RC4", "3DES"}, good, true, "F"},
		{"cert unavailable fails closed", vers(true, false), nil, CertInfo{}, false, "C"},
		{"expired flag ignored when cert not read", vers(true, false), nil, CertInfo{Expired: true}, false, "C"},
	}
	for _, c := range cases {
		if got := rate(c.versions, c.ciphers, c.cert, c.certOK); got != c.want {
			t.Errorf("%s: rate = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := NormalizeHost("example.com"); got != "example.com:443" {
		t.Errorf("NormalizeHost bare = %q", got)
	}
	if got := NormalizeHost("example.com:8443"); got != "example.com:8443" {
		t.Errorf("NormalizeHost with port = %q", got)
	}
}
