// Package report emits structured security findings as JSON Lines (JSONL) so an
// external SIEM — Wazuh in particular — can ingest them via a <localfile> with
// log_format json. Every tool in the toolkit can call Emit to append one event;
// emission is best-effort and never aborts the calling tool.
//
// Log location: $SPEEDTEST_REPORT_LOG if set, else <user-config>/speedtest/security.jsonl.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Severity classifies how urgent a finding is. Values mirror common SIEM scales
// so Wazuh rules can map them to alert levels directly.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Event is one security finding. Data carries tool-specific fields and is
// flattened into the JSON object so Wazuh decoders can address them directly.
type Event struct {
	Time     time.Time      `json:"time"`
	Tool     string         `json:"tool"`
	Target   string         `json:"target,omitempty"`
	Severity Severity       `json:"severity"`
	Summary  string         `json:"summary"`
	Data     map[string]any `json:"data,omitempty"`
}

// EnvLog is the environment variable overriding the default log location.
const EnvLog = "SPEEDTEST_REPORT_LOG"

// Path returns the JSONL log location, creating the parent directory. When
// SPEEDTEST_REPORT_LOG is set it is used verbatim (its parent is created).
func Path() (string, error) {
	if p := os.Getenv(EnvLog); p != "" {
		if dir := filepath.Dir(p); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", err
			}
		}
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "speedtest")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "security.jsonl"), nil
}

var writeMu sync.Mutex

// Marshal renders ev as the single-line JSON that is written to the log. It
// fills Time with now when zero and defaults an empty/invalid Severity to info,
// so a caller can never produce a malformed line.
func Marshal(ev Event) ([]byte, error) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if !ev.Severity.Valid() {
		ev.Severity = SeverityInfo
	}
	return json.Marshal(ev)
}

// Emit appends one event to the report log as a JSON line. It is best-effort:
// callers may ignore the error for fire-and-forget telemetry, or check it where
// persistence matters.
func Emit(ev Event) error {
	line, err := Marshal(ev)
	if err != nil {
		return err
	}
	path, err := Path()
	if err != nil {
		return err
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		return err
	}
	return nil
}
