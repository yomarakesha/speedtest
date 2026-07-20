package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/audit"
)

// auditgradeProbe re-runs the security audit and alerts when the letter grade
// falls below the configured minimum, drops versus the last run, or new findings
// appear.
type auditgradeProbe struct {
	spec CheckSpec
}

func newAuditgradeProbe(spec CheckSpec) *auditgradeProbe { return &auditgradeProbe{spec: spec} }

func (p *auditgradeProbe) Name() string   { return "auditgrade" }
func (p *auditgradeProbe) Target() string { return p.spec.Target }
func (p *auditgradeProbe) Interval() time.Duration {
	if p.spec.Interval > 0 {
		return p.spec.Interval.D()
	}
	return time.Hour
}

func (p *auditgradeProbe) Run(ctx context.Context) Result {
	opt := audit.DefaultAuditOptions()
	opt.Active = p.spec.Active
	findings := audit.RunChecks(p.spec.Target, opt, nil, nil)
	report := audit.NewReport(p.spec.Target, findings)

	prev, hadPrev := audit.LoadSnapshot(p.spec.Target)
	alerts := evalAuditGrade(p.spec, prev, hadPrev, report)

	audit.Record(report)
	if err := audit.SaveSnapshot(report); err != nil {
		return Result{Check: "auditgrade", Target: p.spec.Target, Err: err, Alerts: alerts}
	}
	return Result{Check: "auditgrade", Target: p.spec.Target, Alerts: alerts}
}

// gradeRank maps a letter grade to a number where higher is better (A=5 .. F=0),
// so grades can be compared. An unknown grade ranks lowest.
func gradeRank(g string) int {
	switch strings.ToUpper(strings.TrimSpace(g)) {
	case "A":
		return 5
	case "B":
		return 4
	case "C":
		return 3
	case "D":
		return 2
	case "E":
		return 1
	case "F":
		return 0
	}
	return -1
}

// evalAuditGrade produces alerts from an audit report: below the minimum grade,
// a grade drop versus the previous run, and any newly-appeared findings.
func evalAuditGrade(spec CheckSpec, prev audit.Snapshot, hadPrev bool, report audit.Report) []Alert {
	now := time.Now()
	var alerts []Alert

	if spec.MinGrade != "" && gradeRank(report.Grade) < gradeRank(spec.MinGrade) {
		sev := SevWarn
		if report.Grade == "F" {
			sev = SevCrit
		}
		alerts = append(alerts, Alert{
			Time: now, Check: "auditgrade", Target: spec.Target, Severity: sev,
			Title:  fmt.Sprintf("оценка %s ниже минимума %s", report.Grade, spec.MinGrade),
			Detail: fmt.Sprintf("находок: %d", len(report.Findings)),
		})
	}

	if hadPrev {
		if gradeRank(report.Grade) < gradeRank(prev.Grade) {
			alerts = append(alerts, Alert{
				Time: now, Check: "auditgrade", Target: spec.Target, Severity: SevWarn,
				Title:  fmt.Sprintf("оценка упала %s → %s", prev.Grade, report.Grade),
				Detail: "с прошлого прогона",
			})
		}
		diff := audit.DiffReports(prev, report)
		if len(diff.Added) > 0 {
			alerts = append(alerts, Alert{
				Time: now, Check: "auditgrade", Target: spec.Target, Severity: SevWarn,
				Title:  fmt.Sprintf("новых находок: %d", len(diff.Added)),
				Detail: topFindingTitle(diff.Added),
			})
		}
	}
	return alerts
}

// topFindingTitle names the most severe newly-added finding for the alert detail.
func topFindingTitle(added []audit.Finding) string {
	if len(added) == 0 {
		return ""
	}
	top := added[0]
	for _, f := range added[1:] {
		if f.Severity > top.Severity {
			top = f
		}
	}
	return top.Title
}
