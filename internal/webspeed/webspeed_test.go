package webspeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestDownloadLargeBody: a single large response is enough for a reliable figure.
func TestDownloadLargeBody(t *testing.T) {
	body := make([]byte, 4<<20) // 4 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	res, err := Download(context.Background(), srv.URL, 300*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Bytes < int64(len(body)) {
		t.Errorf("bytes = %d, want >= %d", res.Bytes, len(body))
	}
	if !res.Reliable {
		t.Errorf("large body should be reliable, got Reliable=false (bytes=%d)", res.Bytes)
	}
	if res.DownloadMbps <= 0 {
		t.Errorf("DownloadMbps = %v, want > 0", res.DownloadMbps)
	}
}

// TestDownloadRepeatsSnapshot: a tiny response finishes early, so the engine
// re-fetches it for the whole window and accumulates bytes across many fetches.
// This is the camera-snapshot path.
func TestDownloadRepeatsSnapshot(t *testing.T) {
	var hits atomic.Int64
	snapshot := make([]byte, 1024) // 1 KiB, well under minReliableBytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(snapshot)
	}))
	defer srv.Close()

	res, err := Download(context.Background(), srv.URL, 250*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if hits.Load() < 2 {
		t.Errorf("expected the snapshot to be fetched repeatedly, got %d fetches", hits.Load())
	}
	if res.Bytes <= int64(len(snapshot)) {
		t.Errorf("bytes = %d, want > one snapshot (%d) — repeat loop should accumulate",
			res.Bytes, len(snapshot))
	}
}

// TestDownloadHTTPError: a 4xx/5xx status surfaces as an error.
func TestDownloadHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Download(context.Background(), srv.URL, 300*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected an error for HTTP 500, got nil")
	}
}

// TestDownloadSampleCallback: the live sample callback fires during a transfer.
func TestDownloadSampleCallback(t *testing.T) {
	body := make([]byte, 8<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dribble the body so the sampler's 0.1s window elapses at least once.
		for off := 0; off < len(body); off += 64 << 10 {
			end := min(off+64<<10, len(body))
			w.Write(body[off:end])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}))
	defer srv.Close()

	var samples atomic.Int64
	_, err := Download(context.Background(), srv.URL, time.Second, func(float64) {
		samples.Add(1)
	})
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if samples.Load() == 0 {
		t.Error("expected at least one live sample callback")
	}
}
