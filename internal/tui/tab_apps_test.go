package tui

import (
	"strings"
	"testing"

	"speedtest/internal/capture"
)

// TestAppsTabShowsUnavailableWithoutPcap checks the Приложения tab explains
// itself instead of offering a monitor that would just error, when built
// without -tags pcap (the default build, and the only one exercised here).
func TestAppsTabShowsUnavailableWithoutPcap(t *testing.T) {
	tab := newAppsTab()
	tab.SetSize(100, 24)
	out := tab.View()

	at, ok := tab.(*appsTab)
	if !ok {
		t.Fatalf("newAppsTab() = %T, want *appsTab", tab)
	}
	if at.running {
		t.Error("should not be running before Enter")
	}
	if !strings.Contains(out, "Приложения") {
		t.Errorf("frame title missing\n%s", out)
	}
	if !strings.Contains(out, "-tags pcap") {
		t.Errorf("expected pcap-unavailable explanation, got:\n%s", out)
	}
}

// TestAppsTabRefreshRowsFormatsUnattributedBucket checks the PID-0 "system"
// row renders with a dash instead of "0", alongside a normal process row.
func TestAppsTabRefreshRowsFormatsUnattributedBucket(t *testing.T) {
	at := newAppsTab().(*appsTab)
	at.SetSize(120, 24)
	at.procs = []capture.ProcTraffic{
		{PID: 4242, Name: "chrome.exe", RxMbps: 2.5, TxMbps: 0.5},
		{PID: 0, Name: "Система/неизвестно", RxMbps: 0.1, TxMbps: 0.0},
	}
	at.refreshRows()

	rows := at.tbl.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0][0] != "4242" || rows[0][1] != "chrome.exe" {
		t.Errorf("row 0 = %+v, want PID 4242/chrome.exe", rows[0])
	}
	if rows[1][0] != "-" {
		t.Errorf("system row PID = %q, want %q", rows[1][0], "-")
	}
}
