# Microservices Audit/Scan Platform with Python Orchestrator and Wazuh Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing monolithic `speedtest` Go CLI/TUI into a system matching "микросервисная система обеспечения безопасности сетевой инфраструктуры: Python-оркестрация, Go-сервисы аудита и тестирования, мониторинг на базе Wazuh" — two independently deployable Go HTTP microservices (audit, scan/discover) wrapping the existing `internal/audit` and `internal/portscan` engines, a Python FastAPI orchestrator that calls them and aggregates results, and a Wazuh integration that turns findings into SIEM alerts.

**Architecture:** Two new Go binaries (`cmd/audit-svc`, `cmd/scan-svc`) expose the existing `internal/audit` and `internal/portscan` packages over stdlib `net/http` JSON APIs — no changes to the existing CLI/TUI or those packages. A Python FastAPI service (`orchestrator/`) calls both over HTTP, stores job results in SQLite, and writes each finding as a JSON line to a log file that a Wazuh agent tails; a custom Wazuh decoder/ruleset (`deploy/wazuh/`) classifies those lines into alerts by severity. Docker Compose wires the three services together for local/dev deployment.

**Tech Stack:** Go 1.26 stdlib `net/http` (no new Go deps — keeps the existing zero-dependency posture for `internal/*`), Python 3.11+ with FastAPI + httpx + uvicorn (`pip`), stdlib `sqlite3`, Wazuh manager/agent (external, deployed via existing Wazuh Docker images — not built here), Docker Compose.

**Spec:** none — derived directly from the target description given by the user; this plan is the spec.

## Global Constraints

- Do not modify `internal/audit` or `internal/portscan` — wrap them, don't change their public API.
- New Go services live under `cmd/<name>-svc/` in the existing `speedtest` module (they need `internal/...` imports, which only works inside this module tree).
- No new Go module dependencies. Use `net/http` from stdlib for both services.
- Python code lives entirely under `orchestrator/`, with its own `requirements.txt` and virtualenv — never mixed into the Go module.
- Every service (audit-svc, scan-svc, orchestrator) must run standalone via `go run ./cmd/<name>-svc` / `uvicorn app.main:app` and via its own Dockerfile.
- All new code gets tests; Go tests via `go test`, Python tests via `pytest`.
- **No Docker available in the execution environment.** Every "docker compose build/up" verify step in this plan is optional/best-effort — if `docker` isn't on PATH, skip that step, note it as unverified, and rely on `go test` / `pytest` (which do run) for correctness instead. Dockerfiles and compose YAML still get written per the plan; they just can't be verified to build here.
- `active=true` audit checks (default creds, CVE probing, unauthenticated-service probing — see `internal/audit/cli.go`'s `AuditOptions.Active` doc-comment) are intrusive and require operator authorization. The orchestrator API must refuse `active=true` unless the caller also asserts authorization explicitly (see Task 5).

---

## File Structure

```
cmd/
  audit-svc/
    main.go          # HTTP server entrypoint, port from $PORT (default 8081)
  scan-svc/
    main.go          # HTTP server entrypoint, port from $PORT (default 8082)
internal/
  svcaudit/
    handler.go        # POST /audit handler, wraps internal/audit
    handler_test.go
  svcscan/
    handler.go        # POST /scan, POST /discover handlers, wraps internal/portscan
    handler_test.go
deploy/
  docker/
    audit-svc.Dockerfile
    scan-svc.Dockerfile
    orchestrator.Dockerfile
  docker-compose.yml
  wazuh/
    decoder.xml       # custom Wazuh decoder for orchestrator finding lines
    rules.xml         # custom Wazuh rules mapping severity -> alert level
    ossec-localfile-snippet.xml   # agent config snippet to add to ossec.conf
orchestrator/
  requirements.txt
  app/
    __init__.py
    main.py            # FastAPI app, routes
    clients.py         # HTTP clients for audit-svc / scan-svc
    storage.py          # SQLite job/result storage
    wazuh_forward.py    # writes findings as JSON lines for the Wazuh agent to tail
    models.py           # pydantic request/response models
  tests/
    conftest.py
    test_clients.py
    test_storage.py
    test_wazuh_forward.py
    test_main.py
```

Why `internal/svcaudit` / `internal/svcscan` instead of putting handlers directly in `cmd/*/main.go`: keeps `main.go` a thin entrypoint (flags/env/`http.ListenAndServe`) and the handler logic — the part with real behavior worth unit-testing via `httptest` — in a package `go test ./...` picks up the normal way.

---

## Task 1: audit-svc — Go HTTP wrapper around `internal/audit`

**Files:**
- Create: `internal/svcaudit/handler.go`
- Create: `internal/svcaudit/handler_test.go`
- Create: `cmd/audit-svc/main.go`

**Interfaces:**
- Consumes: `audit.RunChecks(target string, opt audit.AuditOptions, emit func(audit.Finding), onSkip func(string)) []audit.Finding`, `audit.NewReport(target string, findings []audit.Finding) audit.Report`, `audit.DefaultAuditOptions() audit.AuditOptions` (all existing, unchanged).
- Produces: `svcaudit.Handler() http.Handler` — later tasks (orchestrator) call this service at `POST /audit` with body `{"target":"host","with_dns":false,"active":false}` and get back `audit.Report` as JSON, or `{"error":"..."}` with 400 on bad input.

- [ ] **Step 1: Write the failing test**

```go
// internal/svcaudit/handler_test.go
package svcaudit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditHandler_BadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAuditHandler_MissingTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAuditHandler_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestAuditHandler_RunsAgainstLoopback(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"target": "127.0.0.1"})
	req := httptest.NewRequest(http.MethodPost, "/audit", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var report struct {
		Target string `json:"target"`
		Grade  string `json:"grade"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, rec.Body.String())
	}
	if report.Target != "127.0.0.1" {
		t.Fatalf("target = %q, want 127.0.0.1", report.Target)
	}
	if report.Grade == "" {
		t.Fatalf("grade is empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/svcaudit/...`
Expected: FAIL — `handler.go` does not exist, `Handler` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/svcaudit/handler.go
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
```

```go
// cmd/audit-svc/main.go
// Command audit-svc runs the audit engine (internal/audit) as a standalone
// HTTP microservice, called by the Python orchestrator's /jobs/audit route.
package main

import (
	"log"
	"net/http"
	"os"

	"speedtest/internal/svcaudit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	log.Printf("audit-svc listening on :%s", port)
	if err := http.ListenAndServe(":"+port, svcaudit.Handler()); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/svcaudit/...`
Expected: PASS (all 4 tests). `TestAuditHandler_RunsAgainstLoopback` takes a few seconds since it runs real passive checks against 127.0.0.1 — that's expected, not flaky.

- [ ] **Step 5: Commit**

```bash
git add internal/svcaudit cmd/audit-svc
git commit -m "feat(svc): add audit-svc HTTP microservice wrapping internal/audit"
```

---

## Task 2: scan-svc — Go HTTP wrapper around `internal/portscan`

**Files:**
- Create: `internal/svcscan/handler.go`
- Create: `internal/svcscan/handler_test.go`
- Create: `cmd/scan-svc/main.go`

**Interfaces:**
- Consumes: `portscan.ParsePorts(spec string) ([]int, error)`, `portscan.ScanLive(ctx, portscan.ScanOptions, onProgress, onOpen) portscan.ScanResult`, `portscan.DiscoverLive(ctx, portscan.DiscoverOptions, onPhase, onHost) ([]portscan.HostResult, error)` (all existing, unchanged).
- Produces: `svcscan.Handler() http.Handler` — orchestrator calls `POST /scan` with `{"host":"1.2.3.4","ports":"1-1024","timeout_ms":500,"workers":500}` → `portscan.ScanResult` JSON; `POST /discover` with `{"cidr":"192.168.1.0/24","timeout_ms":400,"workers":1000}` → `{"hosts":[...portscan.HostResult]}` JSON.

- [ ] **Step 1: Write the failing test**

```go
// internal/svcscan/handler_test.go
package svcscan

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanHandler_MissingHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestScanHandler_ScansLoopback(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "ports": "1-100", "timeout_ms": 200, "workers": 50,
	})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var result struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, rec.Body.String())
	}
	if result.Host != "127.0.0.1" {
		t.Fatalf("host = %q, want 127.0.0.1", result.Host)
	}
}

func TestScanHandler_BadPortSpec(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "ports": "not-a-port-spec"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDiscoverHandler_RunsOnLoopbackCIDR(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"cidr": "127.0.0.1/32", "timeout_ms": 200, "workers": 50, "scan_all": true, "no_icmp": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/discover", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var result struct {
		Hosts []struct {
			IP string `json:"ip"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/svcscan/...`
Expected: FAIL — package/handler does not exist.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/svcscan/handler.go
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
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	workers := req.Workers
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
		return defaultScanPorts(), nil
	}
	return portscan.ParsePorts(spec)
}

func defaultScanPorts() []int {
	ports := make([]int, 0, 1024)
	for p := 1; p <= 1024; p++ {
		ports = append(ports, p)
	}
	return ports
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
	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	ports, err := resolvePorts(req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	workers := req.Workers
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
```

```go
// cmd/scan-svc/main.go
// Command scan-svc runs the port-scan/discovery engine (internal/portscan) as
// a standalone HTTP microservice, called by the Python orchestrator.
package main

import (
	"log"
	"net/http"
	"os"

	"speedtest/internal/svcscan"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	log.Printf("scan-svc listening on :%s", port)
	if err := http.ListenAndServe(":"+port, svcscan.Handler()); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/svcscan/...`
Expected: PASS (all 4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/svcscan cmd/scan-svc
git commit -m "feat(svc): add scan-svc HTTP microservice wrapping internal/portscan"
```

---

## Task 3: Dockerfiles + docker-compose skeleton for the two Go services

**Files:**
- Create: `deploy/docker/audit-svc.Dockerfile`
- Create: `deploy/docker/scan-svc.Dockerfile`
- Create: `deploy/docker-compose.yml` (audit-svc + scan-svc only; orchestrator added in Task 4)

**Interfaces:**
- Consumes: `cmd/audit-svc`, `cmd/scan-svc` build targets from Task 1/2.
- Produces: containers reachable at `http://audit-svc:8081` and `http://scan-svc:8082` on the compose network `netsec`, used by the orchestrator's `AUDIT_SVC_URL` / `SCAN_SVC_URL` env vars in Task 4.

- [ ] **Step 1: Write the Dockerfiles**

```dockerfile
# deploy/docker/audit-svc.Dockerfile
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /audit-svc ./cmd/audit-svc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /audit-svc /audit-svc
ENV PORT=8081
EXPOSE 8081
ENTRYPOINT ["/audit-svc"]
```

```dockerfile
# deploy/docker/scan-svc.Dockerfile
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scan-svc ./cmd/scan-svc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /scan-svc /scan-svc
ENV PORT=8082
EXPOSE 8082
ENTRYPOINT ["/scan-svc"]
```

- [ ] **Step 2: Write docker-compose.yml**

```yaml
# deploy/docker-compose.yml
services:
  audit-svc:
    build:
      context: ..
      dockerfile: deploy/docker/audit-svc.Dockerfile
    ports:
      - "8081:8081"
    networks: [netsec]

  scan-svc:
    build:
      context: ..
      dockerfile: deploy/docker/scan-svc.Dockerfile
    ports:
      - "8082:8082"
    networks: [netsec]

networks:
  netsec:
    driver: bridge
```

- [ ] **Step 3: Verify the images build (optional — skip if `docker` is not installed)**

Run: `docker compose -f deploy/docker-compose.yml build`
Expected: both images build without error. If `docker` isn't on PATH in this environment, skip this step and note in the task report that the Dockerfiles are written but unverified — correctness of Tasks 1–2 is already covered by `go test ./internal/svcaudit/... ./internal/svcscan/...`.

- [ ] **Step 4: Verify the services respond (optional — skip if `docker` is not installed)**

Run: `docker compose -f deploy/docker-compose.yml up -d && curl -s http://localhost:8081/healthz && curl -s http://localhost:8082/healthz && docker compose -f deploy/docker-compose.yml down`
Expected: both curls print `ok`. Same skip rule as Step 3.

- [ ] **Step 5: Commit**

```bash
git add deploy/docker deploy/docker-compose.yml
git commit -m "build(deploy): add Dockerfiles and compose skeleton for audit-svc/scan-svc"
```

---

## Task 4: Python orchestrator skeleton — FastAPI app + HTTP clients + SQLite storage

**Files:**
- Create: `orchestrator/requirements.txt`
- Create: `orchestrator/app/__init__.py`
- Create: `orchestrator/app/models.py`
- Create: `orchestrator/app/clients.py`
- Create: `orchestrator/app/storage.py`
- Create: `orchestrator/app/main.py`
- Create: `orchestrator/tests/conftest.py`
- Create: `orchestrator/tests/test_clients.py`
- Create: `orchestrator/tests/test_storage.py`
- Create: `orchestrator/tests/test_main.py`

**Interfaces:**
- Consumes: `POST http://<audit-svc>/audit` and `POST http://<scan-svc>/discover` from Tasks 1–2.
- Produces: `AuditClient.audit(target: str) -> dict`, `ScanClient.discover(cidr: str) -> list[dict]` (used by Task 5's aggregation route), `Storage.save_job(job_id: str, kind: str, result: dict) -> None` / `Storage.get_job(job_id: str) -> dict | None` (used by Task 5).

- [ ] **Step 1: requirements.txt**

```
# orchestrator/requirements.txt
fastapi==0.115.0
uvicorn==0.30.6
httpx==0.27.2
pytest==8.3.3
pytest-asyncio==0.24.0
respx==0.21.1
```

- [ ] **Step 2: Write failing tests**

```python
# orchestrator/tests/conftest.py
import pytest


@pytest.fixture
def tmp_db_path(tmp_path):
    return str(tmp_path / "orchestrator.db")
```

```python
# orchestrator/tests/test_clients.py
import httpx
import pytest
import respx

from app.clients import AuditClient, ScanClient


@pytest.mark.asyncio
@respx.mock
async def test_audit_client_posts_target_and_returns_report():
    route = respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(200, json={"target": "1.2.3.4", "findings": [], "grade": "A"})
    )
    client = AuditClient(base_url="http://audit-svc:8081")
    report = await client.audit("1.2.3.4")
    assert route.called
    assert report["target"] == "1.2.3.4"
    assert report["grade"] == "A"


@pytest.mark.asyncio
@respx.mock
async def test_audit_client_raises_on_error_status():
    respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(400, json={"error": "target is required"})
    )
    client = AuditClient(base_url="http://audit-svc:8081")
    with pytest.raises(httpx.HTTPStatusError):
        await client.audit("")


@pytest.mark.asyncio
@respx.mock
async def test_scan_client_discover_returns_hosts():
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": [{"ip": "192.168.1.10", "open": []}]})
    )
    client = ScanClient(base_url="http://scan-svc:8082")
    hosts = await client.discover("192.168.1.0/24")
    assert hosts == [{"ip": "192.168.1.10", "open": []}]
```

```python
# orchestrator/tests/test_storage.py
from app.storage import Storage


def test_save_and_get_job(tmp_db_path):
    store = Storage(tmp_db_path)
    store.save_job("job-1", "audit", {"target": "1.2.3.4", "grade": "A"})
    got = store.get_job("job-1")
    assert got["kind"] == "audit"
    assert got["result"]["grade"] == "A"


def test_get_missing_job_returns_none(tmp_db_path):
    store = Storage(tmp_db_path)
    assert store.get_job("missing") is None
```

```python
# orchestrator/tests/test_main.py
from fastapi.testclient import TestClient

from app.main import app


def test_healthz():
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && pip install -r requirements.txt && pytest -v`
Expected: FAIL — `app.clients`, `app.storage`, `app.main` don't exist yet.

- [ ] **Step 4: Write minimal implementation**

```python
# orchestrator/app/models.py
from pydantic import BaseModel


class AuditJobRequest(BaseModel):
    target: str
    with_dns: bool = False
    active: bool = False
    authorized: bool = False  # must be true when active=True — see Task 5's gate


class DiscoverAuditJobRequest(BaseModel):
    cidr: str
    with_dns: bool = False
    active: bool = False
    authorized: bool = False  # must be true when active=True — see Task 5's gate
```

```python
# orchestrator/app/clients.py
"""Thin async HTTP clients for the audit-svc and scan-svc Go microservices."""
import httpx


class AuditClient:
    def __init__(self, base_url: str, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def audit(self, target: str, with_dns: bool = False, active: bool = False) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/audit",
                json={"target": target, "with_dns": with_dns, "active": active},
            )
            resp.raise_for_status()
            return resp.json()


class ScanClient:
    def __init__(self, base_url: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def discover(self, cidr: str) -> list[dict]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/discover", json={"cidr": cidr})
            resp.raise_for_status()
            return resp.json()["hosts"]
```

```python
# orchestrator/app/storage.py
"""SQLite-backed job result storage. No ORM — stdlib sqlite3 is enough for
one table with a JSON blob column."""
import json
import sqlite3
from contextlib import closing


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def save_job(self, job_id: str, kind: str, result: dict) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO jobs (job_id, kind, result_json) VALUES (?, ?, ?)",
                (job_id, kind, json.dumps(result)),
            )
            conn.commit()

    def get_job(self, job_id: str) -> dict | None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT kind, result_json FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        if row is None:
            return None
        kind, result_json = row
        return {"kind": kind, "result": json.loads(result_json)}
```

```python
# orchestrator/app/main.py
import os

from fastapi import FastAPI

from app.clients import AuditClient, ScanClient
from app.storage import Storage

app = FastAPI(title="netsec-orchestrator")

audit_client = AuditClient(base_url=os.environ.get("AUDIT_SVC_URL", "http://audit-svc:8081"))
scan_client = ScanClient(base_url=os.environ.get("SCAN_SVC_URL", "http://scan-svc:8082"))
storage = Storage(os.environ.get("ORCHESTRATOR_DB", "orchestrator.db"))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
```

```python
# orchestrator/app/__init__.py
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && pytest -v`
Expected: PASS (7 tests: 3 clients, 2 storage, 1 healthz — `test_main.py` only has `test_healthz` at this point, wired to real module-level clients/storage which is fine for a smoke test).

- [ ] **Step 6: Commit**

```bash
git add orchestrator
git commit -m "feat(orchestrator): add FastAPI skeleton with audit/scan HTTP clients and SQLite storage"
```

---

## Task 5: Orchestrator aggregation route — discover a subnet, audit every live host, store results

**Files:**
- Modify: `orchestrator/app/main.py`
- Modify: `orchestrator/tests/test_main.py`

**Interfaces:**
- Consumes: `AuditClient.audit`, `ScanClient.discover`, `Storage.save_job` / `Storage.get_job` from Task 4.
- Produces: `POST /jobs/discover-and-audit {"cidr": "..."}` → `{"job_id": "..."}` (202 Accepted, work runs in background); `GET /jobs/{job_id}` → `{"kind": "discover-and-audit", "result": {...}}` or 404. `result` shape: `{"cidr": str, "hosts": [{"ip": str, "audit": <audit.Report dict> | None, "error": str | None}]}`. This is what Task 6's Wazuh forwarder reads. `POST /jobs/discover-and-audit {"cidr": "...", "active": true}` without `"authorized": true` → 403, no job created, no scan runs — intrusive checks (default creds, CVE probing) must not fire without an explicit authorization assertion from the caller.

- [ ] **Step 1: Write the failing test**

```python
# orchestrator/tests/test_main.py (append)
import respx
import httpx
from fastapi.testclient import TestClient

from app.main import app


def test_healthz():
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@respx.mock
def test_discover_and_audit_job_runs_and_can_be_fetched():
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": [{"ip": "10.0.0.5", "open": []}]})
    )
    respx.post("http://audit-svc:8081/audit").mock(
        return_value=httpx.Response(
            200, json={"target": "10.0.0.5", "findings": [], "grade": "A"}
        )
    )

    client = TestClient(app)
    resp = client.post("/jobs/discover-and-audit", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]
    assert job_id

    fetched = client.get(f"/jobs/{job_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["kind"] == "discover-and-audit"
    assert body["result"]["cidr"] == "10.0.0.0/24"
    assert body["result"]["hosts"][0]["ip"] == "10.0.0.5"
    assert body["result"]["hosts"][0]["audit"]["grade"] == "A"


def test_get_unknown_job_returns_404():
    client = TestClient(app)
    resp = client.get("/jobs/does-not-exist")
    assert resp.status_code == 404


def test_active_without_authorized_is_rejected():
    client = TestClient(app)
    resp = client.post("/jobs/discover-and-audit", json={"cidr": "10.0.0.0/24", "active": True})
    assert resp.status_code == 403
    assert "authoriz" in resp.json()["detail"].lower()


@respx.mock
def test_active_with_authorized_is_accepted():
    respx.post("http://scan-svc:8082/discover").mock(
        return_value=httpx.Response(200, json={"hosts": []})
    )
    client = TestClient(app)
    resp = client.post(
        "/jobs/discover-and-audit",
        json={"cidr": "10.0.0.0/24", "active": True, "authorized": True},
    )
    assert resp.status_code == 202
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && pytest tests/test_main.py -v`
Expected: FAIL — `/jobs/discover-and-audit` route (404) not found.

- [ ] **Step 3: Write minimal implementation**

`TestClient` runs `BackgroundTasks` synchronously before returning the response in FastAPI's test mode, so the fetch-right-after-post pattern in the test is safe without added polling.

```python
# orchestrator/app/main.py
import os
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException

from app.clients import AuditClient, ScanClient
from app.models import DiscoverAuditJobRequest
from app.storage import Storage

app = FastAPI(title="netsec-orchestrator")

audit_client = AuditClient(base_url=os.environ.get("AUDIT_SVC_URL", "http://audit-svc:8081"))
scan_client = ScanClient(base_url=os.environ.get("SCAN_SVC_URL", "http://scan-svc:8082"))
storage = Storage(os.environ.get("ORCHESTRATOR_DB", "orchestrator.db"))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


async def _run_discover_and_audit(job_id: str, cidr: str, with_dns: bool, active: bool) -> None:
    hosts_out = []
    try:
        hosts = await scan_client.discover(cidr)
    except Exception as exc:  # noqa: BLE001 - persist the failure, don't crash the background task
        storage.save_job(job_id, "discover-and-audit", {"cidr": cidr, "hosts": [], "error": str(exc)})
        return

    for host in hosts:
        ip = host["ip"]
        try:
            report = await audit_client.audit(ip, with_dns=with_dns, active=active)
            hosts_out.append({"ip": ip, "audit": report, "error": None})
        except Exception as exc:  # noqa: BLE001 - one host's audit failing shouldn't drop the rest
            hosts_out.append({"ip": ip, "audit": None, "error": str(exc)})

    storage.save_job(job_id, "discover-and-audit", {"cidr": cidr, "hosts": hosts_out})


@app.post("/jobs/discover-and-audit", status_code=202)
async def create_discover_and_audit_job(req: DiscoverAuditJobRequest, background_tasks: BackgroundTasks):
    if req.active and not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="active=true requires authorized=true — intrusive checks need explicit operator authorization",
        )
    job_id = str(uuid.uuid4())
    background_tasks.add_task(_run_discover_and_audit, job_id, req.cidr, req.with_dns, req.active)
    return {"job_id": job_id}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = storage.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && pytest tests/test_main.py -v`
Expected: PASS (5 tests: healthz, discover-and-audit happy path, unknown job 404, active-without-authorized 403, active-with-authorized 202).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/app/main.py orchestrator/app/models.py orchestrator/tests/test_main.py
git commit -m "feat(orchestrator): add discover-and-audit background job with authorization gate for active checks"
```

---

## Task 6: Wazuh integration — JSONL finding forwarder + decoder/rules + wiring

**Files:**
- Create: `orchestrator/app/wazuh_forward.py`
- Create: `orchestrator/tests/test_wazuh_forward.py`
- Modify: `orchestrator/app/main.py` (call the forwarder after a discover-and-audit job finishes)
- Create: `deploy/wazuh/decoder.xml`
- Create: `deploy/wazuh/rules.xml`
- Create: `deploy/wazuh/ossec-localfile-snippet.xml`
- Modify: `deploy/docker-compose.yml` (add orchestrator service, mount shared findings volume)

**Interfaces:**
- Consumes: `audit.Report`-shaped dicts (`target`, `findings[].check/severity/title/detail`, `grade`) produced by Task 5's job result.
- Produces: `forward_findings(log_path: str, cidr: str, hosts: list[dict]) -> int` (returns lines written) — one JSON object per line, matched by `deploy/wazuh/decoder.xml`/`rules.xml` on the Wazuh manager once a Wazuh agent's `ossec.conf` monitors `log_path` (see `ossec-localfile-snippet.xml`).

Wazuh itself (manager + agent containers/install) is external infrastructure, not built by this repo — this task ships the artifacts (decoder, rules, agent config snippet) needed to plug the orchestrator's output into an existing or newly-deployed Wazuh stack, per the [Wazuh custom decoders/rules docs](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html).

- [ ] **Step 1: Write the failing test**

```python
# orchestrator/tests/test_wazuh_forward.py
import json

from app.wazuh_forward import forward_findings


def test_forward_findings_writes_one_line_per_finding(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [
        {
            "ip": "10.0.0.5",
            "audit": {
                "target": "10.0.0.5",
                "grade": "D",
                "findings": [
                    {"check": "tls.weak_protocol", "severity": 3, "title": "TLS 1.0 enabled", "detail": "..."},
                    {"check": "http.missing_hsts", "severity": 1, "title": "No HSTS", "detail": "..."},
                ],
            },
            "error": None,
        },
        {"ip": "10.0.0.9", "audit": None, "error": "connection refused"},
    ]

    count = forward_findings(log_path, "10.0.0.0/24", hosts)

    assert count == 2
    lines = open(log_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["source"] == "netsec-orchestrator"
    assert first["cidr"] == "10.0.0.0/24"
    assert first["ip"] == "10.0.0.5"
    assert first["check"] == "tls.weak_protocol"
    assert first["severity"] == 3
    assert first["grade"] == "D"


def test_forward_findings_skips_hosts_with_no_audit(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    hosts = [{"ip": "10.0.0.9", "audit": None, "error": "connection refused"}]

    count = forward_findings(log_path, "10.0.0.0/24", hosts)

    assert count == 0
    assert not open(log_path, encoding="utf-8").read()


def test_forward_findings_appends_across_calls(tmp_path):
    log_path = str(tmp_path / "findings.jsonl")
    host = {"ip": "10.0.0.5", "audit": {"target": "10.0.0.5", "grade": "A", "findings": [
        {"check": "x", "severity": 0, "title": "t", "detail": "d"}
    ]}, "error": None}

    forward_findings(log_path, "10.0.0.0/24", [host])
    forward_findings(log_path, "10.0.0.0/24", [host])

    lines = open(log_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && pytest tests/test_wazuh_forward.py -v`
Expected: FAIL — `app.wazuh_forward` doesn't exist.

- [ ] **Step 3: Write minimal implementation**

```python
# orchestrator/app/wazuh_forward.py
"""Writes audit findings as JSON lines to a log file a Wazuh agent tails
(via a <localfile> block in ossec.conf, log_format json) — see
deploy/wazuh/ossec-localfile-snippet.xml, decoder.xml and rules.xml."""
import json


def forward_findings(log_path: str, cidr: str, hosts: list[dict]) -> int:
    written = 0
    with open(log_path, "a", encoding="utf-8") as f:
        for host in hosts:
            report = host.get("audit")
            if not report:
                continue
            for finding in report.get("findings", []):
                line = {
                    "source": "netsec-orchestrator",
                    "cidr": cidr,
                    "ip": host["ip"],
                    "grade": report.get("grade"),
                    "check": finding.get("check"),
                    "severity": finding.get("severity"),
                    "title": finding.get("title"),
                    "detail": finding.get("detail"),
                }
                f.write(json.dumps(line) + "\n")
                written += 1
    return written
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && pytest tests/test_wazuh_forward.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire the forwarder into the discover-and-audit job**

Edit `orchestrator/app/main.py`:

```python
# add near the top with the other imports
from app.wazuh_forward import forward_findings

# add near the other os.environ.get(...) module-level config
FINDINGS_LOG_PATH = os.environ.get("FINDINGS_LOG_PATH", "/var/log/netsec-orchestrator/findings.jsonl")
```

Then in `_run_discover_and_audit`, replace the final line:

```python
    storage.save_job(job_id, "discover-and-audit", {"cidr": cidr, "hosts": hosts_out})
```

with:

```python
    storage.save_job(job_id, "discover-and-audit", {"cidr": cidr, "hosts": hosts_out})
    forward_findings(FINDINGS_LOG_PATH, cidr, hosts_out)
```

Update the existing background-task test in `orchestrator/tests/test_main.py` to point `FINDINGS_LOG_PATH` at a tmp file so it doesn't try to write to `/var/log` during tests — add near the top of `test_discover_and_audit_job_runs_and_can_be_fetched`:

```python
def test_discover_and_audit_job_runs_and_can_be_fetched(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.FINDINGS_LOG_PATH", str(tmp_path / "findings.jsonl"))
    respx.post("http://scan-svc:8082/discover").mock(
```

(keep the rest of that test body unchanged — only the `def` line and the added `monkeypatch.setattr` change).

- [ ] **Step 6: Run the full orchestrator suite**

Run: `cd orchestrator && pytest -v`
Expected: PASS (all tests, including the updated main test).

- [ ] **Step 7: Write the Wazuh decoder and rules**

```xml
<!-- deploy/wazuh/decoder.xml -->
<decoder name="netsec-orchestrator">
  <program_name>^netsec-orchestrator$</program_name>
</decoder>

<decoder name="netsec-orchestrator-json">
  <parent>netsec-orchestrator</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

```xml
<!-- deploy/wazuh/rules.xml -->
<group name="netsec_orchestrator,">
  <rule id="100100" level="3">
    <decoded_as>netsec-orchestrator-json</decoded_as>
    <field name="source">netsec-orchestrator</field>
    <description>Netsec orchestrator finding: $(check) on $(ip)</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100101" level="7">
    <if_sid>100100</if_sid>
    <field name="severity">^[2-2]$</field>
    <description>Netsec orchestrator: medium-severity finding $(check) on $(ip)</description>
  </rule>

  <rule id="100102" level="10">
    <if_sid>100100</if_sid>
    <field name="severity">^[3-3]$</field>
    <description>Netsec orchestrator: high-severity finding $(check) on $(ip)</description>
  </rule>

  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="severity">^[4-9]$</field>
    <description>Netsec orchestrator: CRITICAL finding $(check) on $(ip) — grade $(grade)</description>
  </rule>
</group>
```

Severity numbers (0=Info,1=Low,2=Medium,3=High,4=Critical) come from `internal/audit/audit.go`'s `Severity` enum — check that file's `const` block before changing these field patterns; if the enum grows past Critical=4, extend rule 100103's pattern.

```xml
<!-- deploy/wazuh/ossec-localfile-snippet.xml -->
<!-- Add this inside <ossec_config> on the host/container running the
     orchestrator, as a Wazuh agent localfile monitor. -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/netsec-orchestrator/findings.jsonl</location>
  <label key="program_name">netsec-orchestrator</label>
</localfile>
```

- [ ] **Step 8: Wire the orchestrator into docker-compose**

```dockerfile
# deploy/docker/orchestrator.Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY orchestrator/app ./app
ENV AUDIT_SVC_URL=http://audit-svc:8081
ENV SCAN_SVC_URL=http://scan-svc:8082
ENV ORCHESTRATOR_DB=/data/orchestrator.db
ENV FINDINGS_LOG_PATH=/var/log/netsec-orchestrator/findings.jsonl
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# deploy/docker-compose.yml (full file, replaces the Task 3 version)
services:
  audit-svc:
    build:
      context: ..
      dockerfile: deploy/docker/audit-svc.Dockerfile
    ports:
      - "8081:8081"
    networks: [netsec]

  scan-svc:
    build:
      context: ..
      dockerfile: deploy/docker/scan-svc.Dockerfile
    ports:
      - "8082:8082"
    networks: [netsec]

  orchestrator:
    build:
      context: ..
      dockerfile: deploy/docker/orchestrator.Dockerfile
    depends_on: [audit-svc, scan-svc]
    ports:
      - "8000:8000"
    volumes:
      - orchestrator-data:/data
      - findings-log:/var/log/netsec-orchestrator
    networks: [netsec]

networks:
  netsec:
    driver: bridge

volumes:
  orchestrator-data:
  findings-log:
```

The `findings-log` named volume is what a Wazuh agent container would also mount (read-only) to tail `findings.jsonl` per `ossec-localfile-snippet.xml` — wiring an actual Wazuh manager/agent pair into this compose file is a deployment-environment decision (existing Wazuh cluster vs. new one) left to whoever operates this stack, per the constraint that Wazuh itself isn't built by this repo.

- [ ] **Step 9: Verify the three-service stack builds and answers (optional — skip if `docker` is not installed)**

Run: `docker compose -f deploy/docker-compose.yml build && docker compose -f deploy/docker-compose.yml up -d && curl -s http://localhost:8000/healthz && docker compose -f deploy/docker-compose.yml down`
Expected: `{"status":"ok"}`. If `docker` isn't on PATH, skip this and note it as unverified — Tasks 1–2's `go test` and Tasks 4–6's `pytest` already cover the actual logic; this step only proves the container wiring.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/app/wazuh_forward.py orchestrator/tests/test_wazuh_forward.py orchestrator/app/main.py orchestrator/tests/test_main.py deploy/wazuh deploy/docker/orchestrator.Dockerfile deploy/docker-compose.yml
git commit -m "feat(wazuh): forward audit findings as JSONL for Wazuh + add decoder/rules, wire orchestrator into compose"
```

---

## Self-Review Notes

- **Coverage:** microservices split (Tasks 1–3), Python orchestration (Tasks 4–5), Wazuh monitoring (Task 6) — all three legs of the target description are covered end-to-end with a runnable path (`docker compose up`) from subnet CIDR to Wazuh-ready JSON lines.
- **Authorization gate:** `active=true` intrusive checks (default creds, CVE probing — `internal/audit`'s `AuditOptions.Active`) are gated in Task 5 behind an explicit `authorized: true` field on `POST /jobs/discover-and-audit`; the orchestrator rejects `active` without `authorized` with 403 before any scan runs. `audit-svc` itself stays a thin, ungated wrapper (Task 1) — the gate lives at the orchestrator boundary since that's the only entry point meant for operators.
- **Not in scope, called out explicitly rather than hidden:** deploying an actual Wazuh manager/agent (external infra, referenced via official docs); Docker-based verification of any service (no Docker in this execution environment — see Global Constraints).
- **Type consistency check:** `AuditClient.audit` / `ScanClient.discover` signatures used identically in Task 4's tests and Task 5's `_run_discover_and_audit`; `Storage.save_job`/`get_job` signature used identically in Task 4 and Task 5; `forward_findings(log_path, cidr, hosts)` signature used identically in Task 6's test and its call site in `main.py`.
