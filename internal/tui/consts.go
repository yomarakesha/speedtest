package tui

import "time"

// Tunables shared across tabs. These were previously scattered magic numbers;
// keeping them here makes the dashboard's behavior easy to see and (via the
// config package) to override.
const (
	// lanPayloadBytes is the per-direction transfer size for a LAN client run.
	lanPayloadBytes = 100 << 20 // 100 MiB

	// httpdlDuration caps a single HTTP download test.
	httpdlDuration = 15 * time.Second

	// scanPortSpec / scanTimeout / scanWorkers configure the single-host scan.
	scanPortSpec = "1-1024"
	scanTimeout  = 500 * time.Millisecond
	scanWorkers  = 500

	// discoverTimeout / discoverWorkers configure the subnet sweep.
	discoverTimeout = 500 * time.Millisecond
	discoverWorkers = 500

	// pingTimeout / pingInterval configure the live ping loop.
	pingTimeout  = 2 * time.Second
	pingInterval = 1 * time.Second
)
