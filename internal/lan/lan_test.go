package lan

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestServeAndClient runs the embedded server on an ephemeral port and measures
// against it over loopback, then confirms the server shuts down when its context
// is canceled.
func TestServeAndClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	info, err := Serve(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if info.Port == "" {
		t.Fatal("Serve returned an empty port")
	}

	target := net.JoinHostPort("127.0.0.1", info.Port)
	res, err := RunClient(context.Background(),
		ClientOptions{Host: target, Bytes: 4 << 20}, nil)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	if res.DownloadMbps <= 0 || res.UploadMbps <= 0 {
		t.Errorf("throughput should be positive: down=%v up=%v",
			res.DownloadMbps, res.UploadMbps)
	}

	// Cancel and confirm the listener stops accepting.
	cancel()
	time.Sleep(50 * time.Millisecond)
	if _, err := RunClient(context.Background(),
		ClientOptions{Host: target, Bytes: 1 << 20}, nil); err == nil {
		t.Error("expected an error connecting after the server was canceled")
	}
}

// TestServeProgressCallback confirms the client streams phase progress.
func TestServeProgressCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	info, err := Serve(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var phases []Phase
	target := net.JoinHostPort("127.0.0.1", info.Port)
	_, err = RunClient(context.Background(),
		ClientOptions{Host: target, Bytes: 2 << 20}, func(p Progress) {
			phases = append(phases, p.Phase)
		})
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	if len(phases) == 0 {
		t.Error("expected at least one progress callback")
	}
}
