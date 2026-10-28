package audit

import (
	"strings"
	"testing"
)

func TestExportHTML(t *testing.T) {
	r := NewReport("example.com", []Finding{
		{Check: "tls.weak_protocol", Severity: High, Title: "Устаревший протокол", Detail: "TLS 1.0"},
		{Check: "http.no_hsts", Severity: Medium, Title: "Нет HSTS"},
	})
	var b strings.Builder
	if err := ExportHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"<!doctype html>", "example.com", "Оценка: D",
		"tls.weak_protocol", "class=\"sev high\"", "class=\"sev medium\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestExportHTMLEscapesFindings(t *testing.T) {
	r := NewReport("x", []Finding{
		{Check: "c", Severity: Low, Title: "<script>alert(1)</script>"},
	})
	var b strings.Builder
	if err := ExportHTML(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") {
		t.Error("finding title was not HTML-escaped")
	}
}
