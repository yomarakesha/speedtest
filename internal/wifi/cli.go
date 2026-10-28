package wifi

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// RunWiFi is the CLI entry point for `speedtest wifi`.
func RunWiFi(args []string) error {
	fs := flag.NewFlagSet("wifi", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	link, aps, err := Survey()
	if err != nil {
		if *asJSON {
			return printJSON(map[string]any{"error": err.Error()})
		}
		return err
	}

	if *asJSON {
		return printJSON(map[string]any{"link": link, "aps": aps})
	}

	if link.Connected {
		fmt.Printf("Подключение: %s\n", link.SSID)
		fmt.Printf("  BSSID:   %s\n", link.BSSID)
		fmt.Printf("  Сигнал:  %d%%\n", link.SignalPct)
		if link.Channel > 0 {
			fmt.Printf("  Канал:   %d (%s)\n", link.Channel, link.Band)
		}
		if link.Security != "" {
			fmt.Printf("  Защита:  %s\n", link.Security)
		}
		if link.Radio != "" {
			fmt.Printf("  Радио:   %s\n", link.Radio)
		}
	} else {
		fmt.Println("Активного Wi-Fi-подключения нет.")
	}

	if len(aps) > 0 {
		fmt.Printf("\nСети поблизости: %d\n\n", len(aps))
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "SSID\tСигнал\tКанал\tДиапазон\tЗащита\tBSSID")
		for _, ap := range aps {
			ssid := ap.SSID
			if ssid == "" {
				ssid = "(скрытая)"
			}
			fmt.Fprintf(w, "%s\t%d%%\t%d\t%s\t%s\t%s\n",
				ssid, ap.SignalPct, ap.Channel, ap.Band, ap.Security, ap.BSSID)
		}
		w.Flush()
	}

	if advice := ChannelAdvice(aps); advice != "" {
		fmt.Printf("\n%s\n", advice)
	}
	fmt.Println("\n(трафик отдельных клиентов Wi-Fi требует режима монитора — здесь не показывается)")
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
