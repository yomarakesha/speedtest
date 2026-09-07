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
