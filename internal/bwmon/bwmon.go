// Package bwmon reports this machine's own live network throughput per
// interface, by sampling the OS byte counters and taking deltas. It is the
// always-available, fully local answer to "what is using my bandwidth" — it
// measures this host only. Seeing other devices' traffic needs the router's
// cooperation or a monitor-mode/capture vantage (see internal/capture).
//
// No third-party dependencies: counters come from PowerShell's
// Get-NetAdapterStatistics on Windows and /proc/net/dev on Linux.
package bwmon

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// NICSample is a point-in-time cumulative byte counter for one interface.
type NICSample struct {
	Name string
	Rx   uint64 // bytes received (cumulative)
	Tx   uint64 // bytes sent (cumulative)
}

// NICRate is the throughput of one interface over a sampling interval.
type NICRate struct {
	Name   string  `json:"name"`
	RxMbps float64 `json:"rx_mbps"`
	TxMbps float64 `json:"tx_mbps"`
	Rx     uint64  `json:"rx_bytes"` // cumulative at end of interval
	Tx     uint64  `json:"tx_bytes"`
}

// ErrNoCounters is returned when interface counters can't be read.
var ErrNoCounters = errors.New("не удалось прочитать счётчики интерфейсов")

// Sample reads the current per-interface byte counters.
func Sample() ([]NICSample, error) {
	switch runtime.GOOS {
	case "windows":
		return sampleWindows()
	case "linux":
		return sampleLinux()
	default:
		return nil, ErrNoCounters
	}
}

// computeRates converts two counter samples taken dt apart into per-interface
// rates. Interfaces missing from prev, or whose counters went backwards (reset
// or interface re-added), are reported at their current cumulative value with a
// zero rate rather than a bogus spike.
func computeRates(prev, cur []NICSample, dt time.Duration) []NICRate {
	secs := dt.Seconds()
	prevByName := make(map[string]NICSample, len(prev))
	for _, p := range prev {
		prevByName[p.Name] = p
	}
	out := make([]NICRate, 0, len(cur))
	for _, c := range cur {
		r := NICRate{Name: c.Name, Rx: c.Rx, Tx: c.Tx}
		if p, ok := prevByName[c.Name]; ok && secs > 0 {
			r.RxMbps = bytesToMbps(sub(c.Rx, p.Rx), secs)
			r.TxMbps = bytesToMbps(sub(c.Tx, p.Tx), secs)
		}
		out = append(out, r)
	}
	return out
}

// sub returns a-b, or 0 if the counter went backwards (wrap/reset).
func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// bytesToMbps converts a byte delta over secs seconds into megabits per second.
func bytesToMbps(deltaBytes uint64, secs float64) float64 {
	if secs <= 0 {
		return 0
	}
	return float64(deltaBytes) * 8 / secs / 1e6
}

// Monitor samples at each interval and invokes cb with the per-interface rates
// until ctx is cancelled. The first callback fires one interval in.
func Monitor(ctx context.Context, interval time.Duration, cb func([]NICRate)) error {
	prev, err := Sample()
	if err != nil {
		return err
	}
	prevAt := time.Now()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			cur, err := Sample()
			if err != nil {
				continue
			}
			cb(computeRates(prev, cur, now.Sub(prevAt)))
			prev, prevAt = cur, now
		}
	}
}

// Totals sums the Rx/Tx rates across all interfaces.
func Totals(rates []NICRate) (rxMbps, txMbps float64) {
	for _, r := range rates {
		rxMbps += r.RxMbps
		txMbps += r.TxMbps
	}
	return
}
