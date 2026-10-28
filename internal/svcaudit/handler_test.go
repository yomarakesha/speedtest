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
