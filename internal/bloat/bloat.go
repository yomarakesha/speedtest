// Package bloat measures bufferbloat: how much TCP latency to a host grows
// while a concurrent HTTP download saturates the link, graded A-F.
package bloat

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"speedtest/internal/ping"
	"speedtest/internal/util"
	"speedtest/internal/webspeed"
)

// Result is the outcome of a bufferbloat run (--json).
type Result struct {
	Host            string  `json:"host"`
	DownloadHost    string  `json:"download_host"`
	BaselineMs      float64 `json:"baseline_ms"`
	LoadedMs        float64 `json:"loaded_ms"`
	IncreaseMs      float64 `json:"increase_ms"`
	Grade           string  `json:"grade"`
	BaselineSamples int     `json:"baseline_samples"`
	LoadedSamples   int     `json:"loaded_samples"`
}

// Grade maps a latency increase (ms) under load to an A-F bufferbloat grade.
// Thresholds are loosely modeled on common bufferbloat test scales (e.g.
// Waveform): small increases barely matter for interactive use, large ones
// make voice/gaming/video calls unusable while the link is saturated.
func Grade(increaseMs float64) string {
	switch {
	case increaseMs < 5:
		return "A"
	case increaseMs < 30:
		return "B"
	case increaseMs < 60:
		return "C"
	case increaseMs < 200:
		return "D"
	default:
		return "F"
	}
}

// Options configures a bufferbloat run.
type Options struct {
	Host          string // ping target, host or host:port
	Port          int    // TCP port to ping (if Host has no :port)
	DownloadHost  string // host to download from while pinging (defaults to Host)
	Duration      time.Duration
	BaselineCount int
	PingTimeout   time.Duration
	PingInterval  time.Duration
}

// Run performs the baseline-then-loaded measurement and returns the Result.
func Run(ctx context.Context, opt Options) (Result, error) {
	pingHost := ping.NormalizeHost(opt.Host, opt.Port)
	downloadHost := opt.DownloadHost
	if downloadHost == "" {
		downloadHost = opt.Host
	}

	baseline, err := measureLatency(ctx, pingHost, opt.BaselineCount, opt.PingTimeout, opt.PingInterval)
	if err != nil {
		return Result{}, err
	}
	if baseline.Received == 0 {
		return Result{}, fmt.Errorf("%s недоступен на этом порту (потери 100%%)", pingHost)
	}

	loadCtx, cancel := context.WithTimeout(ctx, opt.Duration)
	defer cancel()

	dlDone := make(chan struct{})
	go func() {
		defer close(dlDone)
		_, _ = webspeed.Download(loadCtx, "http://"+downloadHost+"/", opt.Duration, nil)
	}()

	loaded := measureLatencyUntilDone(loadCtx, pingHost, opt.PingTimeout, opt.PingInterval)
	<-dlDone

	increase := loaded.AvgMs - baseline.AvgMs
	if increase < 0 {
		increase = 0
	}

	return Result{
		Host:            pingHost,
		DownloadHost:    downloadHost,
		BaselineMs:      baseline.AvgMs,
		LoadedMs:        loaded.AvgMs,
		IncreaseMs:      increase,
		Grade:           Grade(increase),
		BaselineSamples: baseline.Received,
		LoadedSamples:   loaded.Received,
	}, nil
}

// measureLatency runs a fixed-count ping and summarizes it.
func measureLatency(ctx context.Context, host string, count int, timeout, interval time.Duration) (ping.Result, error) {
	opt := ping.Options{Host: host, Count: count, Timeout: timeout, Interval: interval}
	var samples []ping.Sample
	for s := range ping.Probe(ctx, opt) {
		samples = append(samples, s)
	}
	return ping.Summarize(host, count, samples), nil
}

// measureLatencyUntilDone pings continuously until ctx is canceled (used
// alongside the concurrent download) and summarizes the result.
func measureLatencyUntilDone(ctx context.Context, host string, timeout, interval time.Duration) ping.Result {
	opt := ping.Options{Host: host, Count: 0, Timeout: timeout, Interval: interval}
	var samples []ping.Sample
	for s := range ping.Probe(ctx, opt) {
		samples = append(samples, s)
	}
	return ping.Summarize(host, len(samples), samples)
}

// RunBloat is the CLI entry point for `speedtest bloat <host>`.
func RunBloat(args []string) error {
	fs := flag.NewFlagSet("bloat", flag.ContinueOnError)
	port := fs.Int("port", ping.DefaultPort, "TCP port to ping")
	downloadHost := fs.String("download-host", "", "host to download from while pinging (default: same host)")
	duration := fs.Duration("duration", 10*time.Second, "how long to download while measuring loaded latency")
	baselineCount := fs.Int("baseline-count", 10, "number of baseline ping samples before the load")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest bloat <host> [--download-host H] [--duration 10s]")
	}

	opt := Options{
		Host:          pos[0],
		Port:          *port,
		DownloadHost:  *downloadHost,
		Duration:      *duration,
		BaselineCount: *baselineCount,
		PingTimeout:   2 * time.Second,
		PingInterval:  200 * time.Millisecond,
	}

	if !*asJSON {
		fmt.Printf("Замер задержки в покое до %s...\n", ping.NormalizeHost(opt.Host, opt.Port))
	}

	res, err := Run(context.Background(), opt)
	if err != nil {
		return err
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("\nЗадержка в покое:     %.2f мс  (%d проб)\n", res.BaselineMs, res.BaselineSamples)
	fmt.Printf("Задержка под нагрузкой: %.2f мс  (%d проб, скачивание с %s)\n", res.LoadedMs, res.LoadedSamples, res.DownloadHost)
	fmt.Printf("Прирост (bufferbloat): %.2f мс\n", res.IncreaseMs)
	fmt.Printf("Оценка: %s\n", res.Grade)
	return nil
}
