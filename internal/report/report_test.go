package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSeverityValid(t *testing.T) {
	valid := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("Severity(%q).Valid() = false, want true", s)
		}
	}
	for _, s := range []Severity{"", "bogus", "INFO"} {
		if s.Valid() {
			t.Errorf("Severity(%q).Valid() = true, want false", s)
		}
	}
}

func TestMarshalDefaults(t *testing.T) {
	line, err := Marshal(Event{Tool: "headers", Summary: "x"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Event
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Severity != SeverityInfo {
		t.Errorf("empty severity = %q, want info", got.Severity)
	}
	if got.Time.IsZero() {
		t.Error("zero Time was not defaulted to now")
	}
}

func TestMarshalSingleLine(t *testing.T) {
	line, err := Marshal(Event{
		Tool:     "dnssec",
		Target:   "example.com",
		Severity: SeverityHigh,
		Summary:  "нет DMARC",
		Data:     map[string]any{"record": "none"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(line), "\n") {
		t.Errorf("marshaled event contains newline: %q", line)
	}
}

func TestPathUsesEnv(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "sub", "custom.jsonl")
	t.Setenv(EnvLog, custom)
	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != custom {
		t.Errorf("Path() = %q, want %q", got, custom)
	}
	if _, err := os.Stat(filepath.Dir(custom)); err != nil {
		t.Errorf("parent dir not created: %v", err)
	}
}

func TestEmitAppends(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "security.jsonl")
	t.Setenv(EnvLog, logPath)

	for i := 0; i < 3; i++ {
		if err := Emit(Event{Tool: "t", Severity: SeverityLow, Summary: "s", Time: time.Now()}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	for _, l := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Errorf("line not valid JSON: %q (%v)", l, err)
		}
	}
}
