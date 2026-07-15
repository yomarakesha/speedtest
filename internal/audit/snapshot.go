package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshot is a point-in-time audit result stored so a later run can diff
// against it (drift detection: what opened, closed, or changed severity).
type Snapshot struct {
	Target   string    `json:"target"`
	Time     time.Time `json:"time"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
}

// snapshotBaseOverride, when non-empty, replaces the user config dir as the
// snapshot root. It exists so tests can redirect storage to a temp dir.
var snapshotBaseOverride string

// snapshotDir is the per-user directory holding the latest snapshot per target.
func snapshotDir() (string, error) {
	base := snapshotBaseOverride
	if base == "" {
		b, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(b, "speedtest")
	}
	dir := filepath.Join(base, "audit-snapshots")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// snapshotFile maps a target to its snapshot path, sanitising characters that
// are unsafe in filenames so "http://host:8080/" becomes a flat name.
func snapshotFile(target string) (string, error) {
	dir, err := snapshotDir()
	if err != nil {
		return "", err
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, HostOnly(target))
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(dir, safe+".json"), nil
}

// SaveSnapshot writes the report as the latest snapshot for its target,
// overwriting any previous one.
func SaveSnapshot(r Report) error {
	path, err := snapshotFile(r.Target)
	if err != nil {
		return err
	}
	snap := Snapshot{Target: r.Target, Time: time.Now(), Grade: r.Grade, Findings: r.Findings}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadSnapshot returns the last saved snapshot for target. ok is false when none
// exists yet (first audit of this target).
func LoadSnapshot(target string) (Snapshot, bool) {
	path, err := snapshotFile(target)
	if err != nil {
		return Snapshot{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, false
	}
	var snap Snapshot
	if json.Unmarshal(b, &snap) != nil {
		return Snapshot{}, false
	}
	return snap, true
}

// Diff is the change between two audits of the same target.
type Diff struct {
	OldGrade string
	NewGrade string
	Added    []Finding // present now, absent before (new exposure)
	Removed  []Finding // present before, gone now (remediated)
}

// findingKey identifies a finding for diffing: same check + title + evidence is
// treated as the same issue across runs.
func findingKey(f Finding) string {
	return f.Check + "\x00" + f.Title + "\x00" + f.Evidence
}

// DiffReports compares a previous snapshot with the current report.
func DiffReports(old Snapshot, current Report) Diff {
	prev := make(map[string]Finding, len(old.Findings))
	for _, f := range old.Findings {
		prev[findingKey(f)] = f
	}
	cur := make(map[string]Finding, len(current.Findings))
	for _, f := range current.Findings {
		cur[findingKey(f)] = f
	}

	d := Diff{OldGrade: old.Grade, NewGrade: current.Grade}
	for k, f := range cur {
		if _, ok := prev[k]; !ok {
			d.Added = append(d.Added, f)
		}
	}
	for k, f := range prev {
		if _, ok := cur[k]; !ok {
			d.Removed = append(d.Removed, f)
		}
	}
	return d
}

// Changed reports whether anything differs between the two runs.
func (d Diff) Changed() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || d.OldGrade != d.NewGrade
}

// PrintDiff renders a drift report to stdout, worst-severity first within each
// group. Added findings are new exposures; removed ones were remediated.
func PrintDiff(d Diff) {
	fmt.Printf("\nИзменения с прошлого прогона  (оценка: %s → %s)\n", d.OldGrade, d.NewGrade)
	if !d.Changed() {
		fmt.Println("  Без изменений.")
		return
	}
	bySeverity := func(fs []Finding) {
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
	}
	if len(d.Added) > 0 {
		bySeverity(d.Added)
		fmt.Printf("  + Новые (%d):\n", len(d.Added))
		for _, f := range d.Added {
			fmt.Printf("    + [%s] %s\n", f.Severity, f.Title)
		}
	}
	if len(d.Removed) > 0 {
		bySeverity(d.Removed)
		fmt.Printf("  - Устранено (%d):\n", len(d.Removed))
		for _, f := range d.Removed {
			fmt.Printf("    - [%s] %s\n", f.Severity, f.Title)
		}
	}
}
