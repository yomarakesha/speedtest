package audit

import "testing"

func TestDiffReports(t *testing.T) {
	old := Snapshot{
		Target: "example.com", Grade: "C",
		Findings: []Finding{
			{Check: "http.no_hsts", Title: "Нет HSTS", Severity: Medium},
			{Check: "tls.weak_protocol", Title: "TLS 1.0", Severity: High, Evidence: "TLS 1.0"},
		},
	}
	current := NewReport("example.com", []Finding{
		{Check: "http.no_hsts", Title: "Нет HSTS", Severity: Medium},        // unchanged
		{Check: "port.risky_exposed", Title: "Открыт 3389", Severity: High}, // added
	})

	d := DiffReports(old, current)
	if !d.Changed() {
		t.Fatal("diff should report changes")
	}
	if len(d.Added) != 1 || d.Added[0].Check != "port.risky_exposed" {
		t.Errorf("added = %+v, want one port.risky_exposed", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Check != "tls.weak_protocol" {
		t.Errorf("removed = %+v, want one tls.weak_protocol", d.Removed)
	}
}

func TestDiffNoChange(t *testing.T) {
	f := []Finding{{Check: "a", Title: "t", Severity: Low}}
	old := Snapshot{Target: "h", Grade: "B", Findings: f}
	cur := NewReport("h", append([]Finding{}, f...))
	if DiffReports(old, cur).Changed() {
		t.Error("identical runs should not report changes")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	snapshotBaseOverride = t.TempDir()
	t.Cleanup(func() { snapshotBaseOverride = "" })
	r := NewReport("roundtrip.test", []Finding{
		{Check: "x", Title: "y", Severity: High, Evidence: "z"},
	})
	if err := SaveSnapshot(r); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadSnapshot("roundtrip.test")
	if !ok {
		t.Fatal("snapshot not found after save")
	}
	if got.Grade != r.Grade || len(got.Findings) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}
