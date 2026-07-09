package trace

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos := fs.Args()
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest trace <host> [--max N] [--json]")
	}
	host := pos[0]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// JSON mode runs a bounded number of rounds so it terminates cleanly.
	if *rounds <= 0 && *asJSON {
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

	// Bound rounds if requested by canceling after we have seen enough.
	if *rounds > 0 {
		go func() {
			// Rough bound: each round is up to maxHops probes at ~timeout each.
			deadline := time.Duration(*rounds) * time.Duration(*maxHops) * (*timeout + *interval)
			t := time.NewTimer(deadline)
			defer t.Stop()
			select {
			case <-t.C:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	if err := Trace(ctx, Options{
		Host: host, MaxHops: *maxHops, Timeout: *timeout, Interval: *interval,
	}, cb); err != nil {
		return err
	}

	if *asJSON {
		b, _ := json.MarshalIndent(latest, "", "  ")
		fmt.Println(string(b))
	}
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
