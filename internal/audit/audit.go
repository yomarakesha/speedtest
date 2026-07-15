// Package audit provides passive security checks against a target host: TLS
// configuration, certificate hygiene and (later) HTTP security headers. Every
// check returns a slice of Finding; a Report bundles them with an overall
// letter grade. Checks are read-only and non-intrusive — they open normal
// connections and inspect what the server volunteers, nothing more.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
)

// Severity ranks how serious a Finding is.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

// String returns the Russian label for a severity.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "критично"
	case High:
		return "высокая"
	case Medium:
		return "средняя"
	case Low:
		return "низкая"
	default:
		return "инфо"
	}
}

// MarshalJSON emits the severity as its lowercase label rather than an int.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON accepts either the string label written by MarshalJSON or a raw
// integer, so a stored report/snapshot round-trips back to a Severity.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = severityFromLabel(str)
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = Severity(n)
	return nil
}

// severityFromLabel is the inverse of String(): it maps a Russian severity label
// back to its Severity. An unknown label degrades to Info.
func severityFromLabel(label string) Severity {
	switch label {
	case "критично":
		return Critical
	case "высокая":
		return High
	case "средняя":
		return Medium
	case "низкая":
		return Low
	default:
		return Info
	}
}

// Finding is a single issue (or informational note) discovered by a check.
type Finding struct {
	Check    string   `json:"check"`    // stable id, e.g. "tls.weak_protocol"
	Severity Severity `json:"severity"` // how bad
	Title    string   `json:"title"`    // short human summary
	Detail   string   `json:"detail"`   // what/why
	Evidence string   `json:"evidence,omitempty"`
	Tags     []string `json:"tags,omitempty"` // compliance mapping (OWASP/CIS), set by NewReport
}

// Report is the full outcome of auditing one target.
type Report struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
	Grade    string    `json:"grade"`
}

// NewReport sorts findings by descending severity, tags each with its
// compliance mapping, and computes the grade.
func NewReport(target string, findings []Finding) Report {
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})
	for i := range findings {
		if findings[i].Tags == nil {
			findings[i].Tags = complianceTags(findings[i].Check)
		}
	}
	return Report{Target: target, Findings: findings, Grade: grade(findings)}
}

// grade maps the worst finding to a letter: no issues -> A, and every step down
// in worst-severity drops one grade (Low->B, Medium->C, High->D, Critical->F).
func grade(findings []Finding) string {
	worst := Info
	for _, f := range findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	switch worst {
	case Critical:
		return "F"
	case High:
		return "D"
	case Medium:
		return "C"
	case Low:
		return "B"
	default:
		return "A"
	}
}

// PrintJSON writes the report as indented JSON to stdout.
func PrintJSON(r Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// PrintReport renders the report as a human-readable table.
func PrintReport(r Report) {
	fmt.Printf("\nЦель: %s    Оценка: %s\n\n", r.Target, r.Grade)
	if len(r.Findings) == 0 {
		fmt.Println("Проблем не обнаружено.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ВАЖНОСТЬ\tПРОВЕРКА\tОПИСАНИЕ")
	for _, f := range r.Findings {
		detail := f.Title
		if f.Detail != "" {
			detail = f.Title + " — " + f.Detail
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Severity, f.Check, detail)
	}
	tw.Flush()
	fmt.Printf("\nВсего находок: %d.\n", len(r.Findings))
}
