package orchclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := Healthz(context.Background(), srv.URL); err != nil {
		t.Fatalf("Healthz() = %v, want nil", err)
	}
}

func TestHealthz_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := Healthz(context.Background(), srv.URL); err == nil {
		t.Fatal("Healthz() = nil, want error")
	}
}

func TestSubmitDiscoverAndAudit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/jobs/discover-and-audit" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["cidr"] != "10.0.0.0/24" {
			t.Fatalf("cidr = %v, want 10.0.0.0/24", body["cidr"])
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"job_id": "abc-123"})
	}))
	defer srv.Close()

	id, err := SubmitDiscoverAndAudit(context.Background(), srv.URL, DiscoverAuditRequest{CIDR: "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("SubmitDiscoverAndAudit() error = %v", err)
	}
	if id != "abc-123" {
		t.Fatalf("job id = %q, want abc-123", id)
	}
}

func TestSubmitDiscoverAndAudit_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "active=true requires authorized=true"})
	}))
	defer srv.Close()

	_, err := SubmitDiscoverAndAudit(context.Background(), srv.URL, DiscoverAuditRequest{CIDR: "10.0.0.0/24", Active: true})
	if err == nil {
		t.Fatal("SubmitDiscoverAndAudit() = nil error, want a 403 error")
	}
	if got := err.Error(); got != "403 Forbidden: active=true requires authorized=true" {
		t.Fatalf("error = %q", got)
	}
}

func TestGetJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jobs/abc-123" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(Job{
			Kind: "discover-and-audit",
			Result: JobResult{
				Status: "done",
				CIDR:   "10.0.0.0/24",
				Hosts: []HostResult{
					{IP: "10.0.0.5", Audit: &AuditReport{Target: "10.0.0.5", Grade: "A"}},
				},
			},
		})
	}))
	defer srv.Close()

	job, err := GetJob(context.Background(), srv.URL, "abc-123")
	if err != nil {
		t.Fatalf("GetJob() error = %v", err)
	}
	if job.Result.Status != "done" || len(job.Result.Hosts) != 1 {
		t.Fatalf("job = %+v", job)
	}
}

func TestGetJob_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"detail": "job not found"})
	}))
	defer srv.Close()

	_, err := GetJob(context.Background(), srv.URL, "missing")
	if err == nil {
		t.Fatal("GetJob() = nil error, want 404 error")
	}
}

func TestListJobs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "10" {
			t.Fatalf("limit = %q, want 10", r.URL.Query().Get("limit"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"jobs": []JobSummary{
				{JobID: "job-2", Status: "pending", CIDR: "10.0.1.0/24"},
				{JobID: "job-1", Status: "done", CIDR: "10.0.0.0/24", HostCount: 3},
			},
		})
	}))
	defer srv.Close()

	jobs, err := ListJobs(context.Background(), srv.URL, 10)
	if err != nil {
		t.Fatalf("ListJobs() error = %v", err)
	}
	if len(jobs) != 2 || jobs[0].JobID != "job-2" {
		t.Fatalf("jobs = %+v", jobs)
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.OrchestratorURL == "" || c.AuditSvcURL == "" || c.ScanSvcURL == "" {
		t.Fatalf("DefaultConfig() = %+v, want all fields set", c)
	}
}
