// Package ping measures TCP-connect round-trip latency to any host:port.
// Unlike the LAN throughput test, this needs nothing running on the target —
// it works against any device that has at least one open/closed-but-reachable
// TCP port (router, phone, printer, server, ...).
package ping

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"time"

	"speedtest/internal/util"
)

// RunPing is the CLI entry point for `speedtest ping <host>`.
func RunPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	count := fs.Int("count", 5, "number of attempts")
	port := fs.Int("port", 80, "TCP port to probe (if host has no :port)")
	timeout := fs.Duration("timeout", 2*time.Second, "per-attempt timeout")
	interval := fs.Duration("interval", 500*time.Millisecond, "delay between attempts")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: speedtest ping <host[:port]> [--count N] [--port P]")
	}

	host := pos[0]
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, fmt.Sprint(*port))
	}

	fmt.Printf("PING (TCP) %s  -  %d attempts\n", host, *count)

	var rtts []float64
	loss := 0
	for i := 0; i < *count; i++ {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", host, *timeout)
		rtt := time.Since(t0).Seconds() * 1000
		if err != nil {
			loss++
			fmt.Printf("  seq %d: failed (%v)\n", i+1, cleanErr(err))
		} else {
			conn.Close()
			rtts = append(rtts, rtt)
			fmt.Printf("  seq %d: %.2f ms\n", i+1, rtt)
		}
		if i < *count-1 {
			time.Sleep(*interval)
		}
	}

	fmt.Println()
	if len(rtts) == 0 {
		fmt.Printf("%s unreachable on this port (100%% loss).\n", host)
		fmt.Println("Try a different --port (e.g. 443, 22, 445) - the device may")
		fmt.Println("only be reachable on ports it actually has open.")
		return nil
	}

	sort.Float64s(rtts)
	min := rtts[0]
	max := rtts[len(rtts)-1]
	sum := 0.0
	for _, r := range rtts {
		sum += r
	}
	avg := sum / float64(len(rtts))
	lossPct := float64(loss) / float64(*count) * 100

	fmt.Printf("min %.2f / avg %.2f / max %.2f ms   %.0f%% loss (%d/%d)\n",
		min, avg, max, lossPct, len(rtts), *count)
	return nil
}

// cleanErr trims a dial error to its most useful part.
func cleanErr(err error) string {
	if oe, ok := err.(*net.OpError); ok && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}
