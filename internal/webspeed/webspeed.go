// Package webspeed measures download speed from an existing HTTP(S) service on
// a device, without running any agent on that device. It is only meaningful
// when the target actually serves a large enough response; small pages (most
// routers, phones, printers) cannot yield a reliable figure, and upload/true
// throughput is impossible without a cooperating server.
package webspeed

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"speedtest/internal/util"
)

// Result is the outcome of an HTTP download measurement (for --json).
type Result struct {
	URL          string  `json:"url"`
	Bytes        int64   `json:"bytes"`
	Seconds      float64 `json:"seconds"`
	DownloadMbps float64 `json:"download_mbps"`
	Reliable     bool    `json:"reliable"`
}

// minReliableBytes is the smallest transfer we consider meaningful (~2 MiB).
const minReliableBytes = 2 << 20

// RunHTTPDL is the CLI entry point for `speedtest httpdl <url|host>`.
func RunHTTPDL(args []string) error {
	fs := flag.NewFlagSet("httpdl", flag.ContinueOnError)
	duration := fs.Duration("duration", 10*time.Second, "max measurement time")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest httpdl <url|host> [--duration 10s]")
	}
	url := normalizeURL(pos[0])

	if !*asJSON {
		fmt.Printf("Качаю с %s  (макс %s)...\n", url, *duration)
	}

	res, err := download(url, *duration, nil)
	if err != nil {
		return err
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Скачано:  %s за %.1f с\n", util.Bytes(res.Bytes), res.Seconds)
	fmt.Printf("Download: %.2f Мбит/с\n", res.DownloadMbps)
	if !res.Reliable {
		fmt.Println("\n⚠ Мало данных для точного замера — у цели нет крупного HTTP-ресурса.")
		fmt.Println("  Укажите путь к большому файлу, напр.: speedtest httpdl http://ЦЕЛЬ/big.iso")
	}
	return nil
}

// Download is the streaming entry point used by the TUI: it downloads url for
// up to maxDur, calling sample (may be nil) ~10x/second with the instantaneous
// throughput in Mbps, and returns the final Result.
func Download(ctx context.Context, url string, maxDur time.Duration, sample func(float64)) (Result, error) {
	return downloadCtx(ctx, normalizeURL(url), maxDur, sample)
}

// download streams the URL, counting bytes until EOF or the deadline.
func download(url string, maxDur time.Duration, sample func(float64)) (Result, error) {
	return downloadCtx(context.Background(), url, maxDur, sample)
}

func downloadCtx(parent context.Context, url string, maxDur time.Duration, sample func(float64)) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, maxDur)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "speedtest/1.0")

	client := &http.Client{}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("подключение: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Result{}, fmt.Errorf("сервер вернул HTTP %d", resp.StatusCode)
	}

	var total int64
	buf := make([]byte, 64*1024)
	lastN, lastT := int64(0), start
	for {
		n, rerr := resp.Body.Read(buf)
		total += int64(n)
		if sample != nil {
			if dt := time.Since(lastT).Seconds(); dt >= 0.1 {
				sample(float64(total-lastN) * 8 / dt / 1e6)
				lastN, lastT = total, time.Now()
			}
		}
		if rerr != nil {
			break // EOF, deadline (context) or read error: stop and report
		}
	}
	elapsed := time.Since(start)

	return Result{
		URL:          url,
		Bytes:        total,
		Seconds:      elapsed.Seconds(),
		DownloadMbps: util.Mbps(total, elapsed),
		Reliable:     total >= minReliableBytes,
	}, nil
}

// normalizeURL prepends http:// when the argument is a bare host or ip[:port].
func normalizeURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "http://" + s
}
