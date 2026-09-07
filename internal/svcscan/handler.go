// Package svcscan exposes internal/portscan over HTTP so it can run as an
// independent microservice (cmd/scan-svc) called by the Python orchestrator.
package svcscan

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"speedtest/internal/portscan"
)

// maxRequestBody caps the JSON request body svcscan will read — these
// requests are a handful of short fields, never a legitimate reason to
// send more.
const maxRequestBody = 1 << 20 // 1 MiB

// maxWorkers and maxTimeoutMs clamp caller-supplied concurrency/timeout so a
// single request can't spin up an unbounded number of goroutines or pin a
// worker on a multi-hour per-port timeout.
const (
	maxWorkers   = 2000
	maxTimeoutMs = 30000 // 30s
)

func clampWorkers(w int) int {
	if w > maxWorkers {
		return maxWorkers
	}
	return w
}

func clampTimeoutMs(ms int) int {
	if ms > maxTimeoutMs {
		return maxTimeoutMs
	}
	return ms
}

// Handler returns the HTTP handler for the scan service: POST /scan, POST /discover.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", handleScan)
	mux.HandleFunc("/discover", handleDiscover)
	mux.HandleFunc("/healthz", handleHealthz)
	return mux
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type scanRequest struct {
	Host      string `json:"host"`
	Ports     string `json:"ports"`
	TimeoutMs int    `json:"timeout_ms"`
	Workers   int    `json:"workers"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	ports, err := resolvePorts(req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	timeoutMs := clampTimeoutMs(req.TimeoutMs)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	workers := clampWorkers(req.Workers)
	if workers <= 0 {
		workers = 500
	}

	result := portscan.ScanLive(r.Context(), portscan.ScanOptions{
		Host: req.Host, Ports: ports, Timeout: timeout, Workers: workers,
	}, nil, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func resolvePorts(spec string) ([]int, error) {
	if spec == "" {
		spec = "1-1024"
	}
	return portscan.ParsePorts(spec)
}

// resolveDiscoverPorts leaves an empty spec as nil so DiscoverLive applies
// its own compact discovery port set instead of a full 1-1024 scan sweep.
func resolveDiscoverPorts(spec string) ([]int, error) {
	if spec == "" {
		return nil, nil
	}
	return portscan.ParsePorts(spec)
}

type discoverRequest struct {
	CIDR      string `json:"cidr"`
	Ports     string `json:"ports"`
	TimeoutMs int    `json:"timeout_ms"`
	Workers   int    `json:"workers"`
	ScanAll   bool   `json:"scan_all"`
	NoICMP    bool   `json:"no_icmp"`
}

func handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ports, err := resolveDiscoverPorts(req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	timeoutMs := clampTimeoutMs(req.TimeoutMs)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	workers := clampWorkers(req.Workers)
	if workers <= 0 {
		workers = 1000
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	hosts, err := portscan.DiscoverLive(ctx, portscan.DiscoverOptions{
		CIDR: req.CIDR, Ports: ports, Timeout: timeout, Workers: workers,
		ScanAll: req.ScanAll, NoICMP: req.NoICMP,
	}, nil, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
}
