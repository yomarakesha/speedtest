package history

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestExportCSV(t *testing.T) {
	recs := []Record{
		{Time: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC), Kind: KindInternet, DownloadMbps: 100.5, UploadMbps: 20.25, PingMs: 12},
		{Time: time.Date(2026, 7, 9, 12, 5, 0, 0, time.UTC), Kind: KindPing, Target: "8.8.8.8:80", PingMs: 8.3, LossPct: 0},
	}
	var buf bytes.Buffer
	if err := ExportCSV(&buf, recs); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "time,kind,target,download_mbps") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "internet") || !strings.Contains(out, "100.50") {
		t.Errorf("missing internet row: %q", out)
	}
	if !strings.Contains(out, "8.8.8.8:80") {
		t.Errorf("missing ping target: %q", out)
	}
}

func TestExportJSONRoundTrip(t *testing.T) {
	recs := []Record{{Time: time.Now().UTC().Truncate(time.Second), Kind: KindHTTPDL, Target: "http://x/f", DownloadMbps: 42}}
	var buf bytes.Buffer
	if err := ExportJSON(&buf, recs); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "httpdl") {
		t.Errorf("json missing kind: %q", buf.String())
	}
}

func TestAppendLoad(t *testing.T) {
	// Redirect the config dir to a temp location so the real history is untouched.
	t.Setenv("APPDATA", t.TempDir())         // Windows UserConfigDir
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // Linux
	t.Setenv("HOME", t.TempDir())            // macOS fallback

	rec := Record{Kind: KindInternet, DownloadMbps: 55.5, UploadMbps: 11.1, PingMs: 9}
	if err := Append(rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	if got[0].DownloadMbps != 55.5 || got[0].Kind != KindInternet {
		t.Errorf("round-trip mismatch: %+v", got[0])
	}
	if got[0].Time.IsZero() {
		t.Error("Append should have stamped Time")
	}
}
