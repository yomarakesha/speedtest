package tui

import (
	"strings"
	"testing"

	"speedtest/internal/orchclient"

	tea "github.com/charmbracelet/bubbletea"
)

// TestOrchestratorFormRenders checks the default screen prompts for a CIDR
// without needing any of the three services to be reachable.
func TestOrchestratorFormRenders(t *testing.T) {
	ot := newOrchestratorTab().(*orchestratorTab)
	ot.SetSize(100, 30)
	out := ot.View()
	for _, want := range []string{"CIDR", "Проверяю сервисы"} {
		if !strings.Contains(out, want) {
			t.Errorf("form view missing %q\n%s", want, out)
		}
	}
}

// TestOrchestratorHealthLine checks each service renders its own colored dot
// once a health check result has landed, whether it succeeded or failed.
func TestOrchestratorHealthLine(t *testing.T) {
	ot := newOrchestratorTab().(*orchestratorTab)
	ot.SetSize(100, 30)
	ot.healthChecked = true
	ot.orchOK, ot.auditOK = true, true
	ot.scanOK = false
	ot.scanErrS = "connection refused"

	out := ot.View()
	for _, want := range []string{"orchestrator", "audit-svc", "scan-svc", "connection refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("health line missing %q\n%s", want, out)
		}
	}
}

// TestOrchestratorJobsListRenders exercises the list view with fabricated
// jobs, the same way discover_smoke_test.go's MAC test bypasses the network.
func TestOrchestratorJobsListRenders(t *testing.T) {
	ot := newOrchestratorTab().(*orchestratorTab)
	ot.SetSize(100, 30)
	ot.view = orchViewList
	ot.jobs = []orchclient.JobSummary{
		{JobID: "11111111-2222", CIDR: "10.0.0.0/24", Status: "pending", HostCount: 0, CreatedAt: "2026-09-07 12:00:00"},
		{JobID: "33333333-4444", CIDR: "10.0.1.0/24", Status: "done", HostCount: 5, CreatedAt: "2026-09-07 11:00:00"},
	}
	ot.refreshJobsRows()

	out := ot.View()
	for _, want := range []string{"10.0.0.0/24", "pending", "10.0.1.0/24", "done"} {
		if !strings.Contains(out, want) {
			t.Errorf("jobs list missing %q\n%s", want, out)
		}
	}
}

// TestOrchestratorDetailRendersFindings checks the per-host table and the
// selected host's finding list (severity-badged, like the audit tab).
func TestOrchestratorDetailRendersFindings(t *testing.T) {
	ot := newOrchestratorTab().(*orchestratorTab)
	ot.SetSize(100, 30)
	ot.view = orchViewDetail
	ot.detail = &orchclient.Job{
		Kind: "discover-and-audit",
		Result: orchclient.JobResult{
			Status: "done",
			CIDR:   "10.0.0.0/24",
			Hosts: []orchclient.HostResult{
				{
					IP: "10.0.0.5",
					Audit: &orchclient.AuditReport{
						Target: "10.0.0.5",
						Grade:  "D",
						Findings: []orchclient.Finding{
							{Check: "tls.weak_protocol", Severity: "высокая", Title: "TLS 1.0 enabled"},
						},
					},
				},
				{IP: "10.0.0.9", Error: "connection refused"},
			},
		},
	}
	ot.refreshHostsRows()

	out := ot.View()
	for _, want := range []string{"10.0.0.5", "D", "10.0.0.9", "connection refused", "TLS 1.0 enabled"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q\n%s", want, out)
		}
	}
}

// TestOrchestratorEscNavigatesFormAndList checks Esc moves the tab between
// the submit form and the job list, and back, without a live service.
func TestOrchestratorEscNavigatesFormAndList(t *testing.T) {
	ot := newOrchestratorTab().(*orchestratorTab)
	ot.SetSize(100, 30)
	if !ot.Capturing() {
		t.Fatal("form view should start capturing (CIDR input focused)")
	}

	tb, _ := ot.Update(tea.KeyMsg{Type: tea.KeyEsc})
	ot = tb.(*orchestratorTab)
	if ot.view != orchViewList {
		t.Fatalf("view after Esc = %v, want orchViewList", ot.view)
	}
	if ot.Capturing() {
		t.Fatal("list view should not capture raw keystrokes")
	}

	tb, _ = ot.Update(tea.KeyMsg{Type: tea.KeyEsc})
	ot = tb.(*orchestratorTab)
	if ot.view != orchViewForm {
		t.Fatalf("view after second Esc = %v, want orchViewForm", ot.view)
	}
}
