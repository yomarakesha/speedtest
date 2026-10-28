package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestExportSARIFValidShape(t *testing.T) {
	r := NewReport("example.com", []Finding{
		{Check: "tls.weak_protocol", Severity: High, Title: "Слабый протокол", Detail: "TLS 1.0"},
		{Check: "http.no_hsts", Severity: Medium, Title: "Нет HSTS"},
		{Check: "tls.weak_protocol", Severity: High, Title: "Слабый протокол", Detail: "TLS 1.1"},
	})

	var buf bytes.Buffer
	if err := ExportSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}

	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", log["version"])
	}

	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Errorf("results = %d, want 3", len(results))
	}

	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	// Two distinct Check ids -> two rules (deduped).
	if len(rules) != 2 {
		t.Errorf("rules = %d, want 2 (deduped)", len(rules))
	}

	first := results[0].(map[string]any)
	if first["level"] != "error" { // High -> error
		t.Errorf("first level = %v, want error", first["level"])
	}
}

func TestSarifLevelMapping(t *testing.T) {
	cases := map[Severity]string{
		Critical: "error", High: "error", Medium: "warning", Low: "note", Info: "none",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%v) = %q, want %q", sev, got, want)
		}
	}
}
