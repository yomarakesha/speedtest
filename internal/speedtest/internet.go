// Package speedtest measures internet bandwidth using the public Yandex
// Internetometer API (the same endpoints that power https://yandex.ru/internet).
package speedtest

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const probesURL = "https://yandex.ru/internet/api/v0/get-probes"

// userAgent mimics a browser; the API rejects empty/unknown clients.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/124.0 Safari/537.36"

type probe struct {
	URL     string `json:"url"`
	Timeout int    `json:"timeout"` // ms, optional
	Size    int64  `json:"size"`    // upload payload size in KiB
}

type probesList struct {
	Probes []probe `json:"probes"`
}

type probesResponse struct {
	Mid      string     `json:"mid"`
	Latency  probesList `json:"latency"`
	Download probesList `json:"download"`
	Upload   probesList `json:"upload"`
}

// Result holds a completed internet measurement.
type Result struct {
	PingMs       float64 `json:"ping_ms"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
}

// RunInternet is the CLI entry point for `speedtest internet`.
func RunInternet(args []string) error {
	fs := flag.NewFlagSet("internet", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output result as JSON")
	attempts := fs.Int("attempts", 3, "measurement attempts per stream")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 8,
		},
	}

	if !*asJSON {
		fmt.Println("Fetching Yandex probe servers...")
	}
	probes, err := fetchProbes(client)
	if err != nil {
		return fmt.Errorf("get probes: %w", err)
	}

	res := Result{}

	if !*asJSON {
		fmt.Print("Ping...     ")
	}
	res.PingMs = measurePing(client, probes.Latency.Probes, *attempts)
	if !*asJSON {
		fmt.Printf("%.1f ms\n", res.PingMs)
	}

	if !*asJSON {
		fmt.Print("Download... ")
	}
	res.DownloadMbps = measureDownload(client, probes.Download.Probes)
	if !*asJSON {
		fmt.Printf("%.2f Mbps\n", res.DownloadMbps)
	}

	if !*asJSON {
		fmt.Print("Upload...   ")
	}
	res.UploadMbps = measureUpload(client, probes.Upload.Probes)
	if !*asJSON {
		fmt.Printf("%.2f Mbps\n", res.UploadMbps)
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	}
	return nil
}

func fetchProbes(client *http.Client) (*probesResponse, error) {
	req, _ := http.NewRequest(http.MethodGet, probesURL, nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Referer", "https://yandex.ru/internet")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var pr probesResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if len(pr.Download.Probes) == 0 {
		return nil, fmt.Errorf("no download probes returned")
	}
	return &pr, nil
}

// measurePing returns the best (minimum) median RTT across latency probes.
func measurePing(client *http.Client, probes []probe, attempts int) float64 {
	best := 1e9
	for _, p := range probes {
		var samples []float64
		for i := 0; i < attempts+1; i++ { // +1 warmup, discarded
			t0 := time.Now()
			req, _ := http.NewRequest(http.MethodGet, p.URL, nil)
			req.Header.Set("User-Agent", userAgent)
			resp, err := client.Do(req)
			rtt := time.Since(t0).Seconds() * 1000
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if i > 0 { // skip warmup
				samples = append(samples, rtt)
			}
		}
		if len(samples) == 0 {
			continue
		}
		sort.Float64s(samples)
		med := samples[len(samples)/2]
		if med < best {
			best = med
		}
	}
	if best == 1e9 {
		return 0
	}
	return best
}

// measureDownload runs the 50mb probes as parallel streams and reports the
// combined throughput in Mbps.
func measureDownload(client *http.Client, probes []probe) float64 {
	var urls []string
	for _, p := range probes {
		if p.Timeout == 0 { // the big (50mb) probes have no short timeout
			urls = append(urls, p.URL)
		}
	}
	if len(urls) == 0 {
		for _, p := range probes {
			urls = append(urls, p.URL)
		}
	}

	var total atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	for _, u := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("User-Agent", userAgent)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			buf := make([]byte, 64*1024)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					total.Add(int64(n))
				}
				if err != nil {
					return
				}
			}
		}(u)
	}
	wg.Wait()
	elapsed := time.Since(start)

	return float64(total.Load()) * 8 / elapsed.Seconds() / 1e6
}

// measureUpload POSTs zero-filled payloads to the upload probes as parallel
// streams and reports combined throughput in Mbps. Probe Size is in KiB.
func measureUpload(client *http.Client, probes []probe) float64 {
	var use []probe
	for _, p := range probes {
		if p.Timeout == 0 { // the larger payloads
			use = append(use, p)
		}
	}
	if len(use) == 0 {
		use = probes
	}

	var total atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	for _, p := range use {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			size := p.Size * 1024 // KiB -> bytes
			if size <= 0 {
				size = 30 << 20
			}
			body := &countingZeroReader{remaining: size, counter: &total}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, body)
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = size
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(p)
	}
	wg.Wait()
	elapsed := time.Since(start)

	return float64(total.Load()) * 8 / elapsed.Seconds() / 1e6
}

// countingZeroReader streams `remaining` zero bytes and counts what it emits.
type countingZeroReader struct {
	remaining int64
	counter   *atomic.Int64
}

func (r *countingZeroReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = 0
	}
	r.remaining -= n
	r.counter.Add(n)
	return int(n), nil
}
