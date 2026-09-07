// Package orchclient is an HTTP client for the Python orchestrator
// (orchestrator/app/main.py) and the two Go microservices it fronts
// (audit-svc, scan-svc). It exists so the TUI's "Оркестратор" tab can drive
// the same discover-and-audit-and-forward-to-Wazuh pipeline that
// deploy/docker-compose.yml wires up, without leaving the terminal.
package orchclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config holds the three service base URLs. Defaults match the dev-only
// loopback bindings audit-svc/scan-svc get in deploy/docker-compose.yml and
// the orchestrator's own default port.
type Config struct {
	OrchestratorURL string
	AuditSvcURL     string
	ScanSvcURL      string
}

// DefaultConfig reads ORCHESTRATOR_URL / AUDIT_SVC_URL / SCAN_SVC_URL from
// the environment, falling back to localhost defaults.
func DefaultConfig() Config {
	return Config{
		OrchestratorURL: envOr("ORCHESTRATOR_URL", "http://127.0.0.1:8000"),
		AuditSvcURL:     envOr("AUDIT_SVC_URL", "http://127.0.0.1:8081"),
		ScanSvcURL:      envOr("SCAN_SVC_URL", "http://127.0.0.1:8082"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Finding mirrors audit.Finding's JSON shape (internal/audit/audit.go).
// Severity arrives as the Russian label its MarshalJSON emits, not a number.
type Finding struct {
	Check    string   `json:"check"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Tags     []string `json:"tags,omitempty"`
}

// AuditReport mirrors audit.Report's JSON shape.
type AuditReport struct {
	Target   string    `json:"target"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
}

// HostResult is one host's outcome inside a discover-and-audit job. Audit is
// nil when Error is set — the host was found but couldn't be audited.
type HostResult struct {
	IP    string       `json:"ip"`
	Audit *AuditReport `json:"audit"`
	Error string       `json:"error,omitempty"`
}

// JobResult is a discover-and-audit job's result payload. Status is
// "pending" while the background task runs, then "done" or "error".
type JobResult struct {
	Status string       `json:"status"`
	CIDR   string       `json:"cidr"`
	Hosts  []HostResult `json:"hosts"`
	Error  string       `json:"error,omitempty"`
}

// Job is the full GET /jobs/{id} response.
type Job struct {
	Kind   string    `json:"kind"`
	Result JobResult `json:"result"`
}

// JobSummary is one row of GET /jobs — light enough to list regularly.
type JobSummary struct {
	JobID     string `json:"job_id"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	CIDR      string `json:"cidr"`
	HostCount int    `json:"host_count"`
	CreatedAt string `json:"created_at"`
}

// Healthz reports whether baseURL's /healthz answers 200 within ctx.
func Healthz(ctx context.Context, baseURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("статус %d", resp.StatusCode)
	}
	return nil
}

// DiscoverAuditRequest is the body of POST /jobs/discover-and-audit.
// Authorized must be true whenever Active is true — the orchestrator refuses
// intrusive checks otherwise (see the plan's authorization gate).
type DiscoverAuditRequest struct {
	CIDR       string
	WithDNS    bool
	Active     bool
	Authorized bool
}

// SubmitDiscoverAndAudit posts a discover-and-audit job and returns its id.
func SubmitDiscoverAndAudit(ctx context.Context, baseURL string, req DiscoverAuditRequest) (string, error) {
	body, err := json.Marshal(map[string]any{
		"cidr":       req.CIDR,
		"with_dns":   req.WithDNS,
		"active":     req.Active,
		"authorized": req.Authorized,
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/jobs/discover-and-audit", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return "", apiError(resp)
	}
	var out struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.JobID, nil
}

// GetJob fetches one job's current state.
func GetJob(ctx context.Context, baseURL, jobID string) (Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/jobs/"+jobID, nil)
	if err != nil {
		return Job{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Job{}, apiError(resp)
	}
	var out Job
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Job{}, err
	}
	return out, nil
}

// ListJobs fetches the most recent jobs, newest first.
func ListJobs(ctx context.Context, baseURL string, limit int) ([]JobSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/jobs?limit=%d", baseURL, limit), nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	var out struct {
		Jobs []JobSummary `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// apiError extracts FastAPI's {"detail": "..."} or the Go services'
// {"error": "..."} shape from a non-2xx response body.
func apiError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		Detail string `json:"detail"`
		Error  string `json:"error"`
	}
	if json.Unmarshal(b, &out) == nil {
		if out.Detail != "" {
			return fmt.Errorf("%s: %s", resp.Status, out.Detail)
		}
		if out.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, out.Error)
		}
	}
	return fmt.Errorf("%s", resp.Status)
}
