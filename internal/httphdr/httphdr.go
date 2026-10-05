// Package httphdr audits the HTTP security response headers a server sends:
// HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
// Permissions-Policy and cookie flags. It assigns each a weight, sums the
// deductions for missing/weak headers into a 0–100 score and an A–F grade, and
// can emit the finding to the Wazuh report log.
package httphdr

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"speedtest/internal/report"
	"speedtest/internal/util"
)

// Check is the audit outcome for one header.
type Check struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Weight  int    `json:"weight"`
	Note    string `json:"note,omitempty"`
}

// Result is the full audit of one URL.
type Result struct {
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Checks     []Check `json:"checks"`
	Score      int     `json:"score"`
	Grade      string  `json:"grade"`
	Server     string  `json:"server,omitempty"`
}

// weights sum to 100; a missing header deducts its weight from the score.
var weights = []struct {
	Header string
	Weight int
	// ok reports whether the header value is acceptable (present and, where it
	// matters, well-formed). A nil ok means "present with any value is fine".
	ok func(string) bool
}{
	{"Strict-Transport-Security", 25, nil},
	{"Content-Security-Policy", 25, nil},
	{"X-Frame-Options", 15, nil},
	{"X-Content-Type-Options", 15, func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "nosniff") }},
	{"Referrer-Policy", 10, nil},
	{"Permissions-Policy", 10, nil},
}

// analyze scores response headers. It is pure: it takes an http.Header and the
// raw Set-Cookie values and returns the per-header checks plus the 0–100 score.
func analyze(h http.Header, cookies []string) ([]Check, int) {
	score := 100
	var checks []Check
	for _, w := range weights {
		v := h.Get(w.Header)
		present := v != ""
		ok := present && (w.ok == nil || w.ok(v))
		c := Check{Name: w.Header, Present: present, Value: v, Weight: w.Weight}
		if !ok {
			score -= w.Weight
			if present && w.ok != nil {
				c.Note = "значение не распознано как безопасное"
			} else {
				c.Note = "заголовок отсутствует"
			}
		}
		checks = append(checks, c)
	}

	// Cookie flags: deduct only when cookies are set and lack protection.
	if len(cookies) > 0 {
		weak := weakCookies(cookies)
		c := Check{Name: "Cookie flags", Present: true, Weight: 10}
		if len(weak) > 0 {
			score -= 10
			c.Note = "без Secure/HttpOnly/SameSite: " + strings.Join(weak, ", ")
		} else {
			c.Note = "Secure/HttpOnly/SameSite присутствуют"
		}
		checks = append(checks, c)
	}

	if score < 0 {
		score = 0
	}
	return checks, score
}

// weakCookies returns the names of cookies missing Secure, HttpOnly or SameSite.
func weakCookies(setCookie []string) []string {
	var weak []string
	for _, sc := range setCookie {
		name, _, _ := strings.Cut(sc, "=")
		name = strings.TrimSpace(name)
		low := strings.ToLower(sc)
		if !strings.Contains(low, "secure") || !strings.Contains(low, "httponly") || !strings.Contains(low, "samesite") {
			weak = append(weak, name)
		}
	}
	sort.Strings(weak)
	return weak
}

// Grade maps a 0–100 score to a letter. Thresholds are deterministic.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// severityFor maps a grade to a report severity.
func severityFor(grade string) report.Severity {
	switch grade {
	case "A", "B":
		return report.SeverityInfo
	case "C":
		return report.SeverityLow
	case "D":
		return report.SeverityMedium
	default:
		return report.SeverityHigh
	}
}

// normalizeURL prepends https:// when no scheme is present.
func normalizeURL(raw string) string {
	if !strings.Contains(raw, "://") {
		return "https://" + raw
	}
	return raw
}

// Audit fetches url and audits its security headers.
func Audit(url string, timeout time.Duration) (Result, error) {
	url = normalizeURL(url)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // header audit, not a trusting client
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "speedtest/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос: %w", err)
	}
	defer resp.Body.Close()

	checks, score := analyze(resp.Header, resp.Header.Values("Set-Cookie"))
	return Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Checks:     checks,
		Score:      score,
		Grade:      Grade(score),
		Server:     resp.Header.Get("Server"),
	}, nil
}

// RunHeaders is the CLI entry point for `speedtest headers <url>`.
func RunHeaders(args []string) error {
	fs := flag.NewFlagSet("headers", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	wazuh := fs.Bool("wazuh", false, "emit finding to the Wazuh report log")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest headers <url>")
	}

	res, err := Audit(pos[0], *timeout)
	if err != nil {
		return err
	}

	if *wazuh {
		_ = report.Emit(report.Event{
			Tool:     "headers",
			Target:   res.URL,
			Severity: severityFor(res.Grade),
			Summary:  fmt.Sprintf("HTTP security headers: оценка %s (%d/100)", res.Grade, res.Score),
			Data:     map[string]any{"score": res.Score, "grade": res.Grade, "status": res.StatusCode},
		})
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Заголовки безопасности %s (HTTP %d)\n", res.URL, res.StatusCode)
	for _, c := range res.Checks {
		mark := "✓"
		if c.Note != "" && !strings.Contains(c.Note, "присут") {
			mark = "✗"
		}
		line := fmt.Sprintf("  %s %-26s", mark, c.Name)
		if c.Note != "" {
			line += " " + c.Note
		} else if c.Value != "" {
			line += " " + c.Value
		}
		fmt.Println(line)
	}
	if res.Server != "" {
		fmt.Printf("  Server: %s\n", res.Server)
	}
	fmt.Printf("\n  Оценка: %s (%d/100)\n", res.Grade, res.Score)
	return nil
}
