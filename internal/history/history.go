// Package history persists every measurement run as a line of JSON (JSONL) under
// the user's config directory, so the TUI can show trends and the CLI can export
// reports. One record per run; the file is append-only and safe to hand-edit or
// delete.
package history

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Kind labels which measurement a record came from.
type Kind string

const (
	KindInternet Kind = "internet"
	KindLAN      Kind = "lan"
	KindPing     Kind = "ping"
	KindHTTPDL   Kind = "httpdl"
	KindTrace    Kind = "trace"
	KindAudit    Kind = "audit"
)

// Record is one measurement result. Only the fields relevant to Kind are set;
// omitempty keeps each JSONL line compact.
type Record struct {
	Time         time.Time `json:"time"`
	Kind         Kind      `json:"kind"`
	Target       string    `json:"target,omitempty"`
	DownloadMbps float64   `json:"download_mbps,omitempty"`
	UploadMbps   float64   `json:"upload_mbps,omitempty"`
	PingMs       float64   `json:"ping_ms,omitempty"`
	LossPct      float64   `json:"loss_pct,omitempty"`
	Grade        string    `json:"grade,omitempty"`    // audit: overall A–F grade
	Findings     int       `json:"findings,omitempty"` // audit: number of findings
}

// Path returns the JSONL file location, creating the parent directory.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "speedtest")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "history.jsonl"), nil
}

// Append writes one record. Time defaults to now when zero. Append never returns
// an error to callers that want it fire-and-forget; use the returned error only
// where persistence matters.
func Append(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	path, err := Path()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Load reads every record, oldest first. A missing file is not an error (empty
// history). Malformed lines are skipped so one bad write can't break the view.
func Load() ([]Record, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if json.Unmarshal(line, &r) == nil {
			recs = append(recs, r)
		}
	}
	return recs, sc.Err()
}

// ExportJSON writes recs as a JSON array.
func ExportJSON(w io.Writer, recs []Record) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(recs)
}

// ExportCSV writes recs as CSV with a header row.
func ExportCSV(w io.Writer, recs []Record) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{
		"time", "kind", "target", "download_mbps", "upload_mbps", "ping_ms", "loss_pct",
		"grade", "findings",
	}); err != nil {
		return err
	}
	for _, r := range recs {
		findings := ""
		if r.Findings > 0 {
			findings = strconv.Itoa(r.Findings)
		}
		row := []string{
			r.Time.Format(time.RFC3339),
			string(r.Kind),
			r.Target,
			f2(r.DownloadMbps),
			f2(r.UploadMbps),
			f2(r.PingMs),
			f2(r.LossPct),
			r.Grade,
			findings,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

func f2(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// RunHistory is the CLI entry point for `speedtest history [--export csv|json]`.
func RunHistory(args []string) error {
	var export string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--export":
			if i+1 < len(args) {
				export = args[i+1]
				i++
			}
		default:
			if v, ok := cutFlag(args[i], "--export="); ok {
				export = v
			}
		}
	}

	recs, err := Load()
	if err != nil {
		return err
	}

	switch export {
	case "csv":
		return ExportCSV(os.Stdout, recs)
	case "json":
		return ExportJSON(os.Stdout, recs)
	case "":
		// fallthrough to human summary
	default:
		return fmt.Errorf("неизвестный формат экспорта %q (csv|json)", export)
	}

	if len(recs) == 0 {
		fmt.Println("История пуста. Запустите замеры — они сохранятся автоматически.")
		return nil
	}
	fmt.Printf("Записей: %d\n", len(recs))
	for _, r := range recs {
		fmt.Printf("  %s  %-8s  %s\n", r.Time.Format("2006-01-02 15:04"), r.Kind, summarize(r))
	}
	return nil
}

func summarize(r Record) string {
	switch r.Kind {
	case KindInternet, KindLAN:
		return fmt.Sprintf("↓ %.1f  ↑ %.1f Мбит/с  пинг %.0f мс", r.DownloadMbps, r.UploadMbps, r.PingMs)
	case KindHTTPDL:
		return fmt.Sprintf("%s  ↓ %.1f Мбит/с", r.Target, r.DownloadMbps)
	case KindPing:
		return fmt.Sprintf("%s  %.1f мс  потери %.0f%%", r.Target, r.PingMs, r.LossPct)
	case KindTrace:
		return fmt.Sprintf("%s  потери %.0f%%", r.Target, r.LossPct)
	case KindAudit:
		return fmt.Sprintf("%s  оценка %s  находок %d", r.Target, r.Grade, r.Findings)
	}
	return r.Target
}

func cutFlag(arg, prefix string) (string, bool) {
	if len(arg) > len(prefix) && arg[:len(prefix)] == prefix {
		return arg[len(prefix):], true
	}
	return "", false
}
