// Package portscan provides concurrent TCP port scanning for a single host
// (`scan`) and subnet-wide open-port discovery (`discover`).
package portscan

import (
	"context"
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

// ScanOpenPorts scans the ports named by spec (e.g. "22,80,443" or "1-1024")
// on host and returns the open ports, sorted ascending. It is the exported entry
// point other packages (e.g. monitor) use to reuse the scan engine.
func ScanOpenPorts(host, spec string, timeout time.Duration, workers int) ([]int, error) {
	ports, err := parsePorts(spec)
	if err != nil {
		return nil, err
	}
	return scanHost(host, ports, timeout, workers), nil
}

// PortInfo is one open port and its guessed service.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
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
	banner := fs.Bool("banner", false, "grab service banners from open ports")
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
	if *banner {
		AddBanners(target, res.Open, *timeout)
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
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "\nХост: %s%s\n\nПОРТ\tСТАТУС\tСЕРВИС\tБАННЕР\n", target, name)
	for _, p := range res.Open {
		fmt.Fprintf(tw, "%d\tоткрыт\t%s\t%s\n", p.Port, dash(p.Service), dash(p.Banner))
	}
	tw.Flush()
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
	cidr := fs.String("cidr", "", "subnet(s) to sweep, comma-separated (default: auto-detected local /24)")
	portSpec := fs.String("ports", "", "ports per host (default: common services)")
	timeout := fs.Duration("timeout", 400*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 1000, "global concurrent connections")
	scanAll := fs.Bool("all", false, "scan every address, skip the liveness pre-check")
	allSubnets := fs.Bool("all-subnets", false, "sweep every directly-attached subnet, not just one")
	expand := fs.Bool("expand", false, "auto-discover subnets (traceroute + SNMP) and scan them recursively")
	expandDepth := fs.Int("expand-depth", 2, "how many hops of subnets to follow with --expand")
	community := fs.String("snmp-community", "", "SNMP community for --expand route discovery (e.g. public)")
	asJSON := fs.Bool("json", false, "output result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var ports []int
	if *portSpec != "" {
		var err error
		if ports, err = parsePorts(*portSpec); err != nil {
			return err
		}
	} else {
		ports = defaultDiscoverPorts
	}

	if *expand {
		return runDiscoverExpand(SplitCIDRs(*cidr), ports, *timeout, *workers, *expandDepth, *community, *scanAll, *asJSON)
	}

	if *allSubnets {
		return runDiscoverAll(ports, *timeout, *workers, *scanAll, *asJSON)
	}

	// An explicit --cidr may name several subnets; sweep them all via DiscoverLive.
	cidrs := SplitCIDRs(*cidr)
	if len(cidrs) > 1 {
		return runDiscoverCIDRs(cidrs, ports, *timeout, *workers, *scanAll, *asJSON)
	}

	network := ""
	if len(cidrs) == 1 {
		network = cidrs[0]
	}
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

// runDiscoverAll sweeps every directly-attached subnet via DiscoverLive and
// prints the combined result. Progress is not streamed per host here; the
// subnet list is announced up front so the scope is clear.
func runDiscoverAll(ports []int, timeout time.Duration, workers int, scanAll, asJSON bool) error {
	subnets := localSubnets()
	if len(subnets) == 0 {
		return fmt.Errorf("не найдено локальных подсетей для сканирования")
	}
	if !asJSON {
		fmt.Printf("Подсети для сканирования (%d): %s\n\n", len(subnets), strings.Join(subnets, ", "))
	}

	results, err := DiscoverLive(context.Background(),
		DiscoverOptions{AllSubnets: true, Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll},
		nil, nil)
	if err != nil {
		return err
	}
	sortResultsByIP(results)

	if asJSON {
		return printJSON(results)
	}
	if len(results) == 0 {
		fmt.Println("(живых хостов не найдено)")
		return nil
	}
	printDiscoverTable(results)
	return nil
}

// runDiscoverCIDRs sweeps an explicit list of subnets via DiscoverLive and
// prints the combined result. Unreachable/unscannable subnets are skipped; the
// scope is announced up front.
func runDiscoverCIDRs(cidrs []string, ports []int, timeout time.Duration, workers int, scanAll, asJSON bool) error {
	if !asJSON {
		fmt.Printf("Подсети для сканирования (%d): %s\n\n", len(cidrs), strings.Join(cidrs, ", "))
	}

	results, err := DiscoverLive(context.Background(),
		DiscoverOptions{CIDRs: cidrs, Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll},
		nil, nil)
	if err != nil {
		return err
	}
	sortResultsByIP(results)

	if asJSON {
		return printJSON(results)
	}
	if len(results) == 0 {
		fmt.Println("(живых хостов не найдено)")
		return nil
	}
	printDiscoverTable(results)
	return nil
}

// runDiscoverExpand auto-discovers subnets (traceroute + optional SNMP) starting
// from seeds (or the local subnets when empty) and scans everything it finds.
func runDiscoverExpand(seeds []string, ports []int, timeout time.Duration, workers, depth int, community string, scanAll, asJSON bool) error {
	if !asJSON {
		start := "локальные подсети"
		if len(seeds) > 0 {
			start = strings.Join(seeds, ", ")
		}
		snmp := "выкл (задайте --snmp-community)"
		if community != "" {
			snmp = "вкл (community: " + community + ")"
		}
		fmt.Printf("Авто-обнаружение подсетей от: %s\n  глубина: %d, SNMP: %s\n\n", start, depth, snmp)
	}

	res, err := ExpandDiscover(context.Background(),
		ExpandOptions{Seeds: seeds, MaxDepth: depth, Community: community,
			Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll},
		func(cidr, source string) {
			if !asJSON {
				fmt.Printf("  + подсеть %-20s (%s)\n", cidr, source)
			}
		}, nil)
	if err != nil && len(res.Hosts) == 0 {
		return err
	}

	if asJSON {
		return printJSON(res.Hosts)
	}
	fmt.Printf("\nОбнаружено подсетей: %d.\n\n", len(res.Subnets))
	if len(res.Hosts) == 0 {
		fmt.Println("(живых хостов не найдено)")
		return nil
	}
	printDiscoverTable(res.Hosts)
	return nil
}

// sortResultsByIP orders results numerically by IPv4 address (lexical fallback).
func sortResultsByIP(results []HostResult) {
	sort.Slice(results, func(i, j int) bool {
		a, b := net.ParseIP(results[i].IP).To4(), net.ParseIP(results[j].IP).To4()
		if a == nil || b == nil {
			return results[i].IP < results[j].IP
		}
		return string(a) < string(b)
	})
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
