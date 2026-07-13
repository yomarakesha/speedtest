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

// minFetchInterval paces re-fetches of a small URL so a tiny snapshot isn't
// requested thousands of times a second (rate-limit / self-DoS on low-power
// cameras). ~50 req/s. A large file or stream fills a fetch on its own and
// never hits this floor, so real transfers are unaffected.
const minFetchInterval = 20 * time.Millisecond

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

	// Reuse one client so repeated fetches keep the connection alive.
	client := &http.Client{}
	start := time.Now()

	var total, lastN int64
	lastT := start
	fetches := 0
	var firstErr error

	// Keep pulling the URL until the deadline. A big file or a continuous
	// stream (e.g. an MJPEG camera feed) fills the whole window in one fetch;
	// a small snapshot (e.g. /snapshot.jpg) finishes early, so we re-fetch it
	// repeatedly and accumulate bytes to get a sustained figure.
	for ctx.Err() == nil {
		iterStart := time.Now()
		got, err := fetchOnce(ctx, client, url, &total, &lastN, &lastT, sample)
		if err != nil {
			if fetches == 0 {
				firstErr = err // couldn't even start: surface it
			}
			break
		}
		fetches++
		if got == 0 {
			break // server served nothing; avoid a busy loop
		}
		// Pace re-fetches (see minFetchInterval). Sleep counts into elapsed, so
		// the reported Mbps stays honest under this cadence; abort on deadline.
		if d := minFetchInterval - time.Since(iterStart); d > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
	elapsed := time.Since(start)

	if total == 0 {
		if firstErr != nil {
			return Result{}, firstErr
		}
		// Zero bytes across the whole window: the target accepted the connection
		// but never sent a usable response (hung/firewalled), or returned empty.
		// Report it as a failure instead of a bogus 0 Mbps "success".
		return Result{}, fmt.Errorf("нет данных: цель не ответила за %s", maxDur)
	}

	return Result{
		URL:          url,
		Bytes:        total,
		Seconds:      elapsed.Seconds(),
		DownloadMbps: util.Mbps(total, elapsed),
		Reliable:     total >= minReliableBytes,
	}, nil
}

// fetchOnce downloads the URL once, adding to the shared byte counters and
// reporting instantaneous throughput via sample. It returns the bytes read this
// fetch. err is non-nil only on a connect/HTTP failure; EOF and deadline are a
// normal end of the transfer.
func fetchOnce(ctx context.Context, client *http.Client, url string, total, lastN *int64, lastT *time.Time, sample func(float64)) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "speedtest/1.0")

	resp, err := client.Do(req)
	if err != nil {
		// A cancel during connect is just the deadline, not a real error.
		if ctx.Err() != nil {
			return 0, nil
		}
		return 0, fmt.Errorf("подключение: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("сервер вернул HTTP %d", resp.StatusCode)
	}

	var got int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		got += int64(n)
		*total += int64(n)
		if sample != nil {
			if dt := time.Since(*lastT).Seconds(); dt >= 0.1 {
				sample(float64(*total-*lastN) * 8 / dt / 1e6)
				*lastN, *lastT = *total, time.Now()
			}
		}
		if rerr != nil {
			break // EOF, deadline (context) or read error: stop
		}
	}
	return got, nil
}

// normalizeURL prepends http:// when the argument is a bare host or ip[:port].
func normalizeURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "http://" + s
}
