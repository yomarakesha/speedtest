package capture

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"
)

// RunSniff is the CLI entry point for `speedtest sniff`.
func RunSniff(args []string) error {
	fs := flag.NewFlagSet("sniff", flag.ContinueOnError)
	iface := fs.String("iface", "", "capture interface (default: first usable)")
	top := fs.Int("top", 15, "show at most this many talkers")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval")
	resolve := fs.Bool("resolve", false, "reverse-DNS the talkers")
	list := fs.Bool("list", false, "list capture devices and exit")
	asJSON := fs.Bool("json", false, "output as JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !Available() {
		return ErrUnavailable
	}

	if *list {
		devs, err := Devices()
		if err != nil {
			return err
		}
		for _, d := range devs {
			fmt.Printf("%s\t%v\t%s\n", d.Name, d.Addrs, d.Description)
		}
		return nil
	}

	fmt.Println("Пассивный анализ трафика (Ctrl+C — стоп).")
	fmt.Println("Примечание: в коммутируемой сети виден в основном собственный трафик +")
	fmt.Println("широковещание. Для полной картины нужен SPAN-порт или режим монитора Wi-Fi.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	enc := json.NewEncoder(os.Stdout)
	return TopTalkers(ctx, Options{Iface: *iface, Top: *top, Interval: *interval, Resolve: *resolve},
		func(talkers []Talker) {
			if *asJSON {
				_ = enc.Encode(talkers)
				return
			}
			printTalkers(talkers)
		})
}

func printTalkers(talkers []Talker) {
	fmt.Printf("\n[%s] топ собеседников:\n", time.Now().Format("15:04:05"))
	if len(talkers) == 0 {
		fmt.Println("  (пока нет трафика)")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tИмя\tMAC\tПакеты\tОбъём")
	for _, t := range talkers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", t.IP, dash(t.Hostname), dash(t.MAC), t.Packets, humanBytes(t.Bytes))
	}
	w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
