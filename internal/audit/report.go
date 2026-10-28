package audit

import (
	"html/template"
	"io"
	"time"

	"speedtest/internal/history"
)

// Record persists an audit run to the shared history log (fire-and-forget).
func Record(r Report) {
	_ = history.Append(history.Record{
		Time:     time.Now(),
		Kind:     history.KindAudit,
		Target:   r.Target,
		Grade:    r.Grade,
		Findings: len(r.Findings),
	})
}

// htmlReport is the template for a standalone HTML audit report.
var htmlReport = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>Аудит {{.Target}}</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#1f2937}
 h1{margin-bottom:.2rem} .grade{font-size:2.5rem;font-weight:700}
 .A{color:#059669}.B{color:#059669}.C{color:#d97706}.D{color:#dc2626}.F{color:#dc2626}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #e5e7eb;vertical-align:top}
 th{color:#6b7280;font-weight:600;font-size:.8rem;text-transform:uppercase}
 .sev{font-weight:700;white-space:nowrap}
 .critical,.high{color:#dc2626}.medium{color:#d97706}.low{color:#7c3aed}.info{color:#6b7280}
 .muted{color:#6b7280;font-size:.85rem}
</style></head><body>
<h1>Аудит безопасности</h1>
<p class="muted">{{.Target}} · {{.When}}</p>
<p class="grade {{.Grade}}">Оценка: {{.Grade}}</p>
{{if .Findings}}
<table><thead><tr><th>Важность</th><th>Проверка</th><th>Описание</th></tr></thead><tbody>
{{range .Findings}}<tr>
 <td class="sev {{.Class}}">{{.SeverityLabel}}</td>
 <td><code>{{.Check}}</code></td>
 <td>{{.Title}}{{if .Detail}} <span class="muted">— {{.Detail}}</span>{{end}}</td>
</tr>{{end}}
</tbody></table>
{{else}}<p>Проблем не обнаружено.</p>{{end}}
<p class="muted">Всего находок: {{len .Findings}}. Сгенерировано speedtest audit.</p>
</body></html>`))

// htmlFinding decorates a Finding with presentation fields for the template.
type htmlFinding struct {
	Finding
	Class         string
	SeverityLabel string
}

// ExportHTML renders the report as a standalone HTML page.
func ExportHTML(w io.Writer, r Report) error {
	classes := map[Severity]string{
		Critical: "critical", High: "high", Medium: "medium", Low: "low", Info: "info",
	}
	findings := make([]htmlFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = htmlFinding{Finding: f, Class: classes[f.Severity], SeverityLabel: f.Severity.String()}
	}
	return htmlReport.Execute(w, struct {
		Target   string
		Grade    string
		When     string
		Findings []htmlFinding
	}{r.Target, r.Grade, time.Now().Format("2006-01-02 15:04"), findings})
}
