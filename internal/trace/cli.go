package trace

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"time"

	"speedtest/internal/portscan"
	"speedtest/internal/util"
)

// RunTrace is the CLI entry point for `speedtest trace <host>`. It prints a live
// hop table that refreshes in place until interrupted (Ctrl+C), then a final
// snapshot. With --json it runs a fixed number of rounds and prints the result.
func RunTrace(args []string) error {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	maxHops := fs.Int("max", 30, "maximum number of hops")
	timeout := fs.Duration("timeout", time.Second, "per-probe timeout")
	interval := fs.Duration("interval", time.Second, "delay between rounds")
	rounds := fs.Int("rounds", 0, "stop after N rounds (0 = until Ctrl+C)")
	asJSON := fs.Bool("json", false, "output final hop table as JSON")
	doScan := fs.Bool("scan", false, "after tracing, port-scan every responding hop")
	scanPorts := fs.String("ports", "common", "ports to scan on each hop (with --scan): all | common | web | 22,80 | 1-1024")
	scanTimeout := fs.Duration("scan-timeout", 500*time.Millisecond, "per-port connect timeout (with --scan)")
	scanWorkers := fs.Int("scan-workers", 500, "concurrent connections per hop (with --scan)")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest trace <host> [--max N] [--json] [--scan [--ports all]]")
	}
	host := pos[0]

	var ports []int
	if *doScan {
		ports, err = portscan.ParsePorts(*scanPorts)
		if err != nil {
			return err
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Bounded modes so they terminate cleanly: scan needs only one pass to
	// discover the path; plain JSON averages over 3 rounds like before.
	switch {
	case *rounds > 0:
		// explicit --rounds wins
	case *doScan:
		*rounds = 1
	case *asJSON:
		*rounds = 3
	}

	var latest []Hop
	roundLen := 0
	printed := false

	cb := func(hops []Hop) {
		latest = hops
		if *asJSON {
			return
		}
		// Detect a new round (hop table shrank back to TTL 1 growth) is tricky;
		// instead we just repaint the whole table each callback.
		if printed {
			fmt.Printf("\033[%dA", roundLen+2) // cursor up to redraw
		}
		roundLen = printTable(host, hops)
		printed = true
	}

	if err := Trace(ctx, Options{
		Host: host, MaxHops: *maxHops, Timeout: *timeout, Interval: *interval, Rounds: *rounds,
	}, cb); err != nil {
		return err
	}

	if *doScan {
		return scanHops(ctx, host, latest, ports, *scanPorts, *scanTimeout, *scanWorkers, *asJSON)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(latest, "", "  ")
		fmt.Println(string(b))
	}
	return nil
}

// hopScan pairs a traced hop with the ports found open on it.
type hopScan struct {
	TTL  int                 `json:"ttl"`
	Scan portscan.ScanResult `json:"scan"`
}

// scanHops port-scans every responding hop concurrently (the hops themselves in
// parallel; each hop's ports in parallel via ScanHost) and prints a combined
// trace+scan report, so the open ports of each node on the path show at once.
func scanHops(ctx context.Context, target string, hops []Hop, ports []int, spec string, timeout time.Duration, workers int, asJSON bool) error {
	// Unique responding IPs, in path order; the destination counts as a hop too.
	seen := map[string]bool{}
	type hopIP struct {
		ttl int
		ip  string
	}
	var queue []hopIP
	for _, h := range hops {
		if h.Host == "" || seen[h.Host] {
			continue
		}
		seen[h.Host] = true
		queue = append(queue, hopIP{h.TTL, h.Host})
	}

	if !asJSON {
		fmt.Printf("\nСканирую %d узел(ов) пути (порты: %s, %d на хоп)...\n", len(queue), spec, len(ports))
	}

	results := make([]hopScan, len(queue))
	var wg sync.WaitGroup
	// Cap concurrent hosts so a long path does not open tens of thousands of
	// sockets at once; each ScanHost still fans out across its own workers.
	sem := make(chan struct{}, 8)
	for i, q := range queue {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, q hopIP) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = hopScan{TTL: q.ttl, Scan: portscan.ScanHost(q.ip, ports, timeout, workers, true)}
		}(i, q)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].TTL < results[j].TTL })

	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{"target": target, "hops": results}, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	for _, r := range results {
		name := r.Scan.Host
		if r.Scan.Hostname != "" {
			name += " (" + r.Scan.Hostname + ")"
		}
		fmt.Printf("\nХоп %d — %s\n", r.TTL, name)
		if len(r.Scan.Open) == 0 {
			fmt.Println("  открытых портов нет")
			continue
		}
		for _, p := range r.Scan.Open {
			svc := p.Service
			if svc == "" {
				svc = "-"
			}
			fmt.Printf("  %-6d %-12s %s\n", p.Port, svc, p.Banner)
		}
	}
	fmt.Println()
	return nil
}

// printTable renders the hop table and returns the number of rows printed.
func printTable(host string, hops []Hop) int {
	fmt.Printf("ТРАССИРОВКА до %s\n", host)
	fmt.Printf("%-4s %-32s %6s %8s %8s %8s %7s\n",
		"Хоп", "Хост", "Потери", "Посл", "Сред", "Лучш", "Худш")
	for _, h := range hops {
		name := h.Host
		if name == "" {
			name = "*"
		} else if h.Name != "" {
			name = h.Name + " (" + h.Host + ")"
		}
		if len(name) > 32 {
			name = name[:31] + "…"
		}
		if h.Recv == 0 {
			fmt.Printf("%-4d %-32s %5.0f%% %8s %8s %8s %7s\n",
				h.TTL, name, h.LossPct, "-", "-", "-", "-")
			continue
		}
		fmt.Printf("%-4d %-32s %5.0f%% %7.1f %7.1f %7.1f %6.1f\n",
			h.TTL, name, h.LossPct, h.LastMs, h.AvgMs, h.BestMs, h.WorstMs)
	}
	return len(hops)
}
