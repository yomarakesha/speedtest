package portscan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestScanLive(t *testing.T) {
	// Open a listener so exactly one port is guaranteed open.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	closed := openPort + 1 // very likely closed neighbor

	var progressCalls int
	var opens []PortInfo
	res := ScanLive(context.Background(), ScanOptions{
		Host:    "127.0.0.1",
		Ports:   []int{openPort, closed},
		Timeout: 300 * time.Millisecond,
		Workers: 4,
	}, func(done, total int) { progressCalls++ }, func(p PortInfo) { opens = append(opens, p) })

	if len(res.Open) < 1 || res.Open[0].Port != openPort {
		t.Fatalf("expected open port %d, got %+v", openPort, res.Open)
	}
	if len(opens) != 1 || opens[0].Port != openPort {
		t.Errorf("onOpen fired wrong: %+v", opens)
	}
	if progressCalls != 2 {
		t.Errorf("progress calls = %d, want 2", progressCalls)
	}
}
