// Package portscan provides concurrent TCP port scanning for a single host
// (`scan`) and subnet-wide open-port discovery (`discover`).
package portscan

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"speedtest/internal/util"
)

// scanPort attempts a TCP connect; returns true if the port accepts.
func scanPort(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanHost scans the given ports on one host with a bounded worker pool and
// returns the open ports, sorted ascending.
func scanHost(host string, ports []int, timeout time.Duration, workers int) []int {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int, workers)
	var mu sync.Mutex
	var open []int

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if scanPort(host, port, timeout) {
					mu.Lock()
					open = append(open, port)
					mu.Unlock()
				}
			}
		}()
	}
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	sort.Ints(open)
	return open
}

// RunScan is the CLI entry point for `speedtest scan <ip>`.
func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	portSpec := fs.String("ports", "1-1024", "ports to scan (e.g. 22,80,443 or 1-65535)")
	timeout := fs.Duration("timeout", 500*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 500, "concurrent connections")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: speedtest scan <ip> [--ports ...]")
	}
	target := pos[0]

	ports, err := parsePorts(*portSpec)
	if err != nil {
		return err
	}

	fmt.Printf("Scanning %s  (%d ports, timeout %s)\n", target, len(ports), *timeout)
	start := time.Now()
	open := scanHost(target, ports, *timeout, *workers)
	elapsed := time.Since(start)

	if len(open) == 0 {
		fmt.Printf("No open ports found (%.1fs).\n", elapsed.Seconds())
		return nil
	}
	fmt.Printf("\nPORT     STATE  SERVICE\n")
	for _, p := range open {
		fmt.Printf("%-8d open   %s\n", p, serviceName(p))
	}
	fmt.Printf("\n%d open port(s) in %.1fs.\n", len(open), elapsed.Seconds())
	return nil
}

// RunDiscover is the CLI entry point for `speedtest discover`.
func RunDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	cidr := fs.String("cidr", "", "subnet to sweep (default: auto-detected local /24)")
	portSpec := fs.String("ports", "", "ports per host (default: common services)")
	timeout := fs.Duration("timeout", 400*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 1000, "global concurrent connections")
	if err := fs.Parse(args); err != nil {
		return err
	}

	network := *cidr
	if network == "" {
		auto, err := localCIDR()
		if err != nil {
			return fmt.Errorf("auto-detect subnet: %w (pass --cidr)", err)
		}
		network = auto
		fmt.Printf("Auto-detected subnet: %s\n", network)
	}

	hosts, err := hostsInCIDR(network)
	if err != nil {
		return err
	}

	var ports []int
	if *portSpec == "" {
		ports = defaultDiscoverPorts
	} else if ports, err = parsePorts(*portSpec); err != nil {
		return err
	}

	fmt.Printf("Sweeping %d hosts x %d ports (timeout %s)...\n\n",
		len(hosts), len(ports), *timeout)

	type finding struct {
		ip   string
		open []int
	}
	results := make([]finding, len(hosts))

	// Global connection budget across all hosts.
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	var scanned atomic.Int64

	for i, h := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			var mu sync.Mutex
			var open []int
			var inner sync.WaitGroup
			for _, p := range ports {
				inner.Add(1)
				sem <- struct{}{}
				go func(port int) {
					defer inner.Done()
					defer func() { <-sem }()
					if scanPort(host, port, *timeout) {
						mu.Lock()
						open = append(open, port)
						mu.Unlock()
					}
				}(p)
			}
			inner.Wait()
			sort.Ints(open)
			results[i] = finding{ip: host, open: open}
			scanned.Add(1)
		}(i, h)
	}
	wg.Wait()

	found := 0
	fmt.Printf("%-16s OPEN PORTS\n", "HOST")
	for _, r := range results {
		if len(r.open) == 0 {
			continue
		}
		found++
		fmt.Printf("%-16s %s\n", r.ip, formatPorts(r.open))
	}
	if found == 0 {
		fmt.Println("(no hosts with open ports found)")
	} else {
		fmt.Printf("\n%d host(s) with open ports.\n", found)
	}
	return nil
}

// formatPorts renders open ports with service labels, e.g. "22(ssh) 80(http)".
func formatPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if s := serviceName(p); s != "" {
			parts = append(parts, fmt.Sprintf("%d(%s)", p, s))
		} else {
			parts = append(parts, fmt.Sprint(p))
		}
	}
	return joinSpace(parts)
}

func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}
