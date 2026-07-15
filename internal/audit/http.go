package audit

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// headerCheck describes one expected security response header.
type headerCheck struct {
	name  string
	check string
	sev   Severity
	title string
}

// securityHeaders is the set of response headers assessed by AuditHTTP.
var securityHeaders = []headerCheck{
	{"Strict-Transport-Security", "http.no_hsts", High,
		"Отсутствует HSTS (Strict-Transport-Security)"},
	{"Content-Security-Policy", "http.no_csp", Medium,
		"Отсутствует Content-Security-Policy"},
	{"X-Frame-Options", "http.no_frame_options", Medium,
		"Отсутствует X-Frame-Options (риск clickjacking)"},
	{"X-Content-Type-Options", "http.no_content_type_options", Low,
		"Отсутствует X-Content-Type-Options: nosniff"},
	{"Referrer-Policy", "http.no_referrer_policy", Low,
		"Отсутствует Referrer-Policy"},
}

// AuditHTTP fetches url and evaluates its security-relevant response headers.
// A bare host is assumed https:// so HSTS can be assessed; an explicit http://
// is honored so plain-HTTP services (e.g. on alternate ports) can be audited.
func AuditHTTP(url string, timeout time.Duration) ([]Finding, error) {
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // assess the first response's headers
		},
	}
	return auditHTTP(url, client, timeout)
}

// auditHTTP is the client-injectable core of AuditHTTP; tests supply a client
// that trusts the httptest self-signed certificate.
func auditHTTP(url string, client *http.Client, timeout time.Duration) ([]Finding, error) {
	url = normalizeURL(url)
	client.Timeout = timeout
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "speedtest-audit/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось запросить %s: %w", url, err)
	}
	defer resp.Body.Close()

	var findings []Finding
	for _, h := range securityHeaders {
		if resp.Header.Get(h.name) == "" {
			findings = append(findings, Finding{
				Check: h.check, Severity: h.sev, Title: h.title,
			})
		}
	}
	findings = append(findings, serverBannerFinding(resp)...)
	findings = append(findings, cookieFindings(resp, strings.HasPrefix(url, "https://"))...)
	findings = append(findings, httpRuleFindings(resp)...)
	return findings, nil
}

// httpRuleFindings runs the declarative rule engine over the response: its
// headers, a bounded slice of the body, and the Server header as a banner (so a
// version-based rule can fire on it too).
func httpRuleFindings(resp *http.Response) []Finding {
	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return DefaultRuleEngine().Eval(MatchInput{
		Banner:  resp.Header.Get("Server"),
		Headers: headers,
		Body:    string(body),
		Status:  resp.StatusCode,
	})
}

// serverBannerFinding notes a Server header that leaks a version, which aids
// fingerprinting.
func serverBannerFinding(resp *http.Response) []Finding {
	server := resp.Header.Get("Server")
	if server == "" || !strings.ContainsAny(server, "0123456789") {
		return nil
	}
	return []Finding{{
		Check: "http.server_version", Severity: Low,
		Title:  "Заголовок Server раскрывает версию ПО",
		Detail: server,
	}}
}

// cookieFindings flags Set-Cookie values missing Secure/HttpOnly protections.
func cookieFindings(resp *http.Response, https bool) []Finding {
	var out []Finding
	for _, c := range resp.Cookies() {
		var missing []string
		if https && !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) > 0 {
			out = append(out, Finding{
				Check: "http.insecure_cookie", Severity: Medium,
				Title:    "Cookie без флагов защиты",
				Detail:   c.Name + ": нет " + strings.Join(missing, ", "),
				Evidence: c.Name,
			})
		}
	}
	return out
}

// normalizeURL keeps an explicit scheme as given (so an http:// service can be
// audited directly) and defaults a bare host to https:// so header checks — HSTS
// in particular — are meaningful.
func normalizeURL(url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}
	return "https://" + url
}
