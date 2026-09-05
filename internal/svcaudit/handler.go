// Package svcaudit exposes internal/audit over HTTP so it can run as an
// independent microservice (cmd/audit-svc) called by the Python orchestrator.
package svcaudit

import (
	"encoding/json"
	"net/http"

	"speedtest/internal/audit"
)

type auditRequest struct {
	Target  string `json:"target"`
	WithDNS bool   `json:"with_dns"`
	Active  bool   `json:"active"` // intrusive checks — caller must be authorized
}

// Handler returns the HTTP handler for the audit service: POST /audit.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/audit", handleAudit)
	mux.HandleFunc("/healthz", handleHealthz)
	return mux
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req auditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
		return
	}

	opt := audit.DefaultAuditOptions()
	opt.WithDNS = req.WithDNS
	opt.Active = req.Active

	findings := audit.RunChecks(req.Target, opt, nil, nil)
	report := audit.NewReport(req.Target, findings)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
