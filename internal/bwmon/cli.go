package bwmon

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"time"
)

// RunBWMon is the CLI entry point for `speedtest bwmon`.
func RunBWMon(args []string) error {
	fs := flag.NewFlagSet("bwmon", flag.ContinueOnError)
	interval := fs.Duration("interval", 2*time.Second, "sampling interval")
	count := fs.Int("count", 0, "number of samples then stop (0 = until Ctrl+C)")
	asJSON := fs.Bool("json", false, "output samples as JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interval < 200*time.Millisecond {
		*interval = 200 * time.Millisecond
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !*asJSON {
		fmt.Printf("Пропускная способность интерфейсов (интервал %s, Ctrl+C — стоп)\n", *interval)
	}

	enc := json.NewEncoder(os.Stdout)
	n := 0
	err := Monitor(ctx, *interval, func(rates []NICRate) {
		if *asJSON {
			_ = enc.Encode(rates)
		} else {
			printRates(rates)
		}
		n++
		if *count > 0 && n >= *count {
			stop()
		}
	})
	return err
}

// printRates renders one sampling tick: active interfaces sorted by total
// throughput, plus an aggregate line.
func printRates(rates []NICRate) {
	active := make([]NICRate, 0, len(rates))
	for _, r := range rates {
		if r.RxMbps >= 0.01 || r.TxMbps >= 0.01 {
			active = append(active, r)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].RxMbps+active[i].TxMbps > active[j].RxMbps+active[j].TxMbps
	})

	rx, tx := Totals(rates)
	fmt.Printf("\n[%s]  всего ↓ %6.2f ↑ %6.2f Мбит/с\n",
		time.Now().Format("15:04:05"), rx, tx)
	if len(active) == 0 {
		fmt.Println("  (нет активного трафика)")
		return
	}
	for _, r := range active {
		fmt.Printf("  %-28s ↓ %7.2f  ↑ %7.2f Мбит/с\n", trunc(r.Name, 28), r.RxMbps, r.TxMbps)
	}
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
