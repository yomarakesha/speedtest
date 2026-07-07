// Package portscan provides concurrent TCP port scanning for a single host
// (`scan`) and subnet-wide open-port discovery (`discover`).
package portscan

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
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

// PortInfo is one open port and its guessed service.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ScanResult is the outcome of scanning a single host.
type ScanResult struct {
	Host     string     `json:"host"`
	Hostname string     `json:"hostname,omitempty"`
	Open     []PortInfo `json:"open"`
}

// RunScan is the CLI entry point for `speedtest scan <ip>`.
func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	portSpec := fs.String("ports", "1-1024", "ports to scan (e.g. 22,80,443 or 1-65535)")
	timeout := fs.Duration("timeout", 500*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 500, "concurrent connections")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest scan <ip> [--ports ...]")
	}
	target := pos[0]

	ports, err := parsePorts(*portSpec)
	if err != nil {
		return err
	}

	if !*asJSON {
		fmt.Printf("Сканирую %s  (портов: %d, таймаут %s)\n", target, len(ports), *timeout)
	}
	start := time.Now()
	open := scanHost(target, ports, *timeout, *workers)
	elapsed := time.Since(start)

	res := ScanResult{
		Host:     target,
		Hostname: reverseDNS(target, time.Second),
		Open:     toPortInfos(open),
	}

	if *asJSON {
		return printJSON(res)
	}

	name := ""
	if res.Hostname != "" {
		name = "  (" + res.Hostname + ")"
	}
	if len(open) == 0 {
		fmt.Printf("Открытых портов не найдено на %s%s (%.1f с).\n", target, name, elapsed.Seconds())
		return nil
	}
	fmt.Printf("\nХост: %s%s\n\nПОРТ     СТАТУС   СЕРВИС\n", target, name)
	for _, p := range res.Open {
		fmt.Printf("%-8d открыт   %s\n", p.Port, p.Service)
	}
	fmt.Printf("\nОткрытых портов: %d за %.1f с.\n", len(open), elapsed.Seconds())
	return nil
}

// toPortInfos attaches service names to a sorted list of open ports.
func toPortInfos(ports []int) []PortInfo {
	out := make([]PortInfo, 0, len(ports))
	for _, p := range ports {
		out = append(out, PortInfo{Port: p, Service: serviceName(p)})
	}
	return out
}

// HostResult is one discovered host with identity and open ports.
type HostResult struct {
	IP       string     `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	MAC      string     `json:"mac,omitempty"`
	Vendor   string     `json:"vendor,omitempty"`
	Open     []PortInfo `json:"open"`
}

// RunDiscover is the CLI entry point for `speedtest discover`.
func RunDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	cidr := fs.String("cidr", "", "subnet to sweep (default: auto-detected local /24)")
	portSpec := fs.String("ports", "", "ports per host (default: common services)")
	timeout := fs.Duration("timeout", 400*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 1000, "global concurrent connections")
	scanAll := fs.Bool("all", false, "scan every address, skip the liveness pre-check")
	asJSON := fs.Bool("json", false, "output result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	network := *cidr
	if network == "" {
		auto, err := localCIDR()
		if err != nil {
			return fmt.Errorf("не удалось определить подсеть: %w (укажите --cidr)", err)
		}
		network = auto
		if !*asJSON {
			fmt.Printf("Определена подсеть: %s\n", network)
		}
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

	// Phase 1: liveness pre-check so we only deep-scan hosts that exist.
	targets := hosts
	if !*scanAll {
		if !*asJSON {
			fmt.Printf("Проверяю %d адресов на живые хосты...\n", len(hosts))
		}
		targets = filterAlive(hosts, *timeout, *workers)
		if !*asJSON {
			fmt.Printf("Живых хостов: %d.\n", len(targets))
		}
	}
	if len(targets) == 0 {
		if *asJSON {
			return printJSON([]HostResult{})
		}
		fmt.Println("(живых хостов не найдено)")
		return nil
	}

	// Phase 2: full port scan of the live hosts.
	if !*asJSON {
		fmt.Printf("Сканирую %d хост(ов) x %d портов (таймаут %s)...\n\n",
			len(targets), len(ports), *timeout)
	}

	results := make([]HostResult, len(targets))
	sem := make(chan struct{}, *workers) // global connection budget
	var wg sync.WaitGroup

	for i, h := range targets {
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
			results[i] = HostResult{IP: host, Open: toPortInfos(open)}
		}(i, h)
	}
	wg.Wait()

	// Enrich with identity: ARP (MAC + vendor) and reverse DNS.
	enrich(results)

	if *asJSON {
		return printJSON(results)
	}
	printDiscoverTable(results)
	return nil
}

// enrich fills in Hostname, MAC and Vendor for each result.
func enrich(results []HostResult) {
	arp := arpTable()
	var wg sync.WaitGroup
	for i := range results {
		if mac, ok := arp[results[i].IP]; ok {
			results[i].MAC = mac
			results[i].Vendor = vendorForMAC(mac)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].Hostname = reverseDNS(results[i].IP, time.Second)
		}(i)
	}
	wg.Wait()
}

// printDiscoverTable renders results as an aligned table.
func printDiscoverTable(results []HostResult) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ХОСТ\tИМЯ\tMAC\tПРОИЗВОДИТЕЛЬ\tОТКРЫТЫЕ ПОРТЫ")
	found := 0
	for _, r := range results {
		ports := "-"
		if len(r.Open) > 0 {
			ports = formatPorts(r.Open)
			found++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.IP, dash(r.Hostname), dash(r.MAC), dash(r.Vendor), ports)
	}
	tw.Flush()
	fmt.Printf("\nЖивых хостов: %d, с открытыми портами: %d.\n", len(results), found)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// formatPorts renders open ports with service labels, e.g. "22(ssh) 80(http)".
func formatPorts(ports []PortInfo) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Service != "" {
			parts = append(parts, fmt.Sprintf("%d(%s)", p.Port, p.Service))
		} else {
			parts = append(parts, fmt.Sprint(p.Port))
		}
	}
	return strings.Join(parts, " ")
}

// printJSON writes v as indented JSON to stdout.
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
