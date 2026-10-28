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
	"strconv"
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
// on host and returns the open ports, sorted ascending. host may be a name or an
// IP; a name is resolved once before scanning. It is the exported entry point
// other packages (e.g. monitor) use to reuse the scan engine.
func ScanOpenPorts(host, spec string, timeout time.Duration, workers int) ([]int, error) {
	ports, err := parsePorts(spec)
	if err != nil {
		return nil, err
	}
	ip, err := ResolveTarget(context.Background(), host, resolveTimeout)
	if err != nil {
		return nil, err
	}
	return scanHost(ip, ports, timeout, workers), nil
}

// resolveTimeout bounds the one up-front DNS lookup a scan performs.
const resolveTimeout = 5 * time.Second

// PortInfo is one open port and its guessed service.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// ScanResult is the outcome of scanning a single host. Host is the address that
// was actually scanned; Hostname is the name it was reached by (or a reverse
// lookup). Warning carries a non-fatal caveat about the result, Error the reason
// no scan happened at all.
type ScanResult struct {
	Host     string     `json:"host"`
	Hostname string     `json:"hostname,omitempty"`
	Open     []PortInfo `json:"open"`
	Warning  string     `json:"warning,omitempty"`
	Error    string     `json:"error,omitempty"`

	UDP        []UDPResult      `json:"udp,omitempty"`
	Web        []WebInfo        `json:"web,omitempty"`
	Subdomains *SubdomainResult `json:"subdomains,omitempty"`
}

// RunScan is the CLI entry point for `speedtest scan <ip|host|cidr|range>...`.
func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	portSpec := fs.String("ports", "1-1024", "ports: 22,80 | 1-65535 | all | common | web | db | ...")
	timeout := fs.Duration("timeout", 500*time.Millisecond, "per-port connect timeout")
	workers := fs.Int("workers", 500, "concurrent connections")
	banner := fs.Bool("banner", false, "identify services (banner / HTTP Server / TLS cert)")
	subdomains := fs.Bool("subdomains", true, "when a domain has open ports, also search for other subdomains (DNS dictionary, MX/NS, TLS certificates, crt.sh)")
	noCT := fs.Bool("no-ct", false, "skip the crt.sh Certificate Transparency lookup during the subdomain search")
	resolveSubs := fs.Bool("resolve-subs", false, "resolve subdomains found from certificates/CT to addresses (slower, more DNS traffic)")
	fingerprint := fs.Bool("fingerprint", true, "fingerprint open web ports (title, Server, technologies)")
	udpSpec := fs.String("udp", "", "also scan these UDP ports (e.g. 53,161 or \"common\" for the built-in set)")
	web := fs.Bool("web", false, "shortcut: only probe common web ports and fingerprint them")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest scan <ip|хост|cidr|диапазон> [--ports ...] [--banner]\nпресеты портов: %s",
			strings.Join(PresetNames(), ", "))
	}

	// The --web shortcut narrows the scan to the common web ports and forces the
	// fingerprint on, so "scan a website" is one flag.
	if *web {
		*portSpec = webPortSpec
		*fingerprint = true
	}

	ports, err := parsePorts(*portSpec)
	if err != nil {
		return err
	}
	udpPorts, err := parseUDPSpec(*udpSpec)
	if err != nil {
		return err
	}
	var targets []string
	for _, p := range pos {
		hs, err := ExpandTargets(p)
		if err != nil {
			return err
		}
		targets = append(targets, hs...)
	}

	opt := scanOpts{
		ports: ports, udpPorts: udpPorts, timeout: *timeout, workers: *workers,
		banner: *banner, fingerprint: *fingerprint, subdomains: *subdomains,
		noCT: *noCT, resolveSubs: *resolveSubs, quiet: *asJSON,
	}
	var all []ScanResult
	for _, target := range targets {
		res, err := scanTarget(target, opt)
		if err != nil {
			if len(targets) == 1 {
				return err
			}
			res = ScanResult{Host: target, Error: err.Error()}
			if !*asJSON {
				fmt.Printf("%s: %v\n\n", target, err)
			}
		}
		all = append(all, res)
	}
	if *asJSON {
		if len(all) == 1 {
			return printJSON(all[0])
		}
		return printJSON(all)
	}
	return nil
}

// scanOpts carries RunScan's flags into scanTarget.
type scanOpts struct {
	ports, udpPorts                 []int
	timeout                         time.Duration
	workers                         int
	banner, fingerprint, subdomains bool
	noCT, resolveSubs, quiet        bool
}

// scanTarget runs the full TCP/UDP/web/subdomain scan of one target and, unless
// quiet, prints its report.
func scanTarget(target string, o scanOpts) (ScanResult, error) {
	ip, err := ResolveTarget(context.Background(), target, resolveTimeout)
	if err != nil {
		return ScanResult{}, err
	}
	if warn := loopbackWarning(target, ip); warn != "" && !o.quiet {
		fmt.Println(warn)
	}

	if !o.quiet {
		fmt.Printf("Сканирую %s  (портов: %d, таймаут %s)\n", describeTarget(target, ip), len(o.ports), o.timeout)
	}
	start := time.Now()
	open := scanHost(ip, o.ports, o.timeout, o.workers)
	elapsed := time.Since(start)

	res := ScanResult{
		Host:     ip,
		Hostname: hostnameFor(target, ip),
		Open:     toPortInfos(open),
	}
	if o.banner {
		AddServiceBanners(ip, res.Open, 2*time.Second)
	}

	// UDP sweep runs regardless of the TCP outcome: some hosts only answer on UDP.
	if len(o.udpPorts) > 0 {
		if !o.quiet {
			fmt.Printf("Проверяю UDP-портов: %d...\n", len(o.udpPorts))
		}
		res.UDP = ScanUDP(context.Background(), ip, o.udpPorts, udpTimeout(o.timeout), o.workers)
	}

	// Fingerprint the open web ports: what software answers, and on which page.
	if o.fingerprint && len(open) > 0 {
		res.Web = FingerprintWeb(context.Background(), ip, target, open, 4*time.Second)
	}

	// Open ports on a named host make its neighbours worth knowing: the same zone
	// usually holds more hosts than the one name the user happened to type.
	if o.subdomains && target != ip && len(open) > 0 {
		if !o.quiet {
			fmt.Printf("\nИщу субдомены %s...\n", baseDomain(target))
		}
		sub := EnumSubdomains(context.Background(), SubdomainOptions{
			Domain: target, Addr: ip, Ports: open, Timeout: 2 * time.Second, Workers: 100,
			NoCT: o.noCT, Resolve: o.resolveSubs,
		})
		res.Subdomains = &sub
	}

	if o.quiet {
		return res, nil
	}

	label := describeTarget(target, ip)
	if res.Hostname != "" && res.Hostname != target {
		label += "  (" + res.Hostname + ")"
	}
	if len(open) == 0 && len(openUDP(res.UDP)) == 0 {
		fmt.Printf("Открытых портов не найдено на %s (%.1f с).\n\n", label, elapsed.Seconds())
		return res, nil
	}
	if len(open) > 0 {
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintf(tw, "\nХост: %s\n\nПОРТ\tСТАТУС\tСЕРВИС\tБАННЕР\n", label)
		for _, p := range res.Open {
			fmt.Fprintf(tw, "%d\tоткрыт\t%s\t%s\n", p.Port, dash(p.Service), dash(p.Banner))
		}
		tw.Flush()
		fmt.Printf("\nОткрытых портов (TCP): %d за %.1f с.\n", len(open), elapsed.Seconds())
	}
	printUDP(res.UDP)
	printWeb(res.Web)
	printSubdomains(res.Subdomains)
	fmt.Println()
	return res, nil
}

// ScanHost scans one host's ports and returns the result, with reverse DNS and
// optional service identification. It is the programmatic entry point reused
// by other subcommands (e.g. `trace --scan`).
func ScanHost(host string, ports []int, timeout time.Duration, workers int, banner bool) ScanResult {
	res := ScanResult{
		Host:     host,
		Hostname: reverseDNS(host, time.Second),
		Open:     toPortInfos(scanHost(host, ports, timeout, workers)),
	}
	if banner {
		AddServiceBanners(host, res.Open, 2*time.Second)
	}
	return res
}

// ExpandTargets turns a target spec into a host list: a single host/IP, a CIDR
// ("192.168.1.0/24") or a last-octet range ("192.168.1.10-50").
func ExpandTargets(spec string) ([]string, error) {
	if strings.Contains(spec, "/") {
		return hostsInCIDR(spec)
	}
	if base, hi, ok := strings.Cut(spec, "-"); ok {
		ip := net.ParseIP(base).To4()
		end, err := strconv.Atoi(hi)
		if ip != nil && err == nil && end >= int(ip[3]) && end <= 255 {
			var out []string
			for o := int(ip[3]); o <= end; o++ {
				out = append(out, fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], o))
			}
			return out, nil
		}
	}
	return []string{spec}, nil
}

// webPortSpec is the port set the --web shortcut scans.
const webPortSpec = "80,81,443,591,2480,3000,4443,4567,5000,7001,8000,8008,8080,8081,8088,8090,8180,8443,8843,8880,9000,9080,9090,9443,10443"

// parseUDPSpec expands a --udp value into a port list. "" means no UDP scan;
// "common" (or "default"/"all") means the built-in service set; anything else is
// parsed like a normal port spec.
func parseUDPSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	switch spec {
	case "":
		return nil, nil
	case "common", "default", "all":
		return commonUDPPorts, nil
	default:
		return parsePorts(spec)
	}
}

// udpTimeout gives a UDP probe a longer wait than TCP: a datagram has no
// handshake, so a slow service needs time to answer before silence is assumed.
func udpTimeout(base time.Duration) time.Duration {
	if base < time.Second {
		return time.Second
	}
	return base
}

// openUDP returns only the UDP results that are open or open|filtered — the ones
// worth showing; definite "closed" ports are noise.
func openUDP(res []UDPResult) []UDPResult {
	var out []UDPResult
	for _, r := range res {
		if r.State != UDPClosed {
			out = append(out, r)
		}
	}
	return out
}

// printUDP renders the interesting UDP results (open / open|filtered).
func printUDP(res []UDPResult) {
	shown := openUDP(res)
	if len(shown) == 0 {
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "\nUDP-порты\n\nПОРТ\tСОСТОЯНИЕ\tСЕРВИС\tОТВЕТ\n")
	open := 0
	for _, r := range shown {
		if r.State == UDPOpen {
			open++
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", r.Port, r.State, dash(r.Service), dash(r.Reply))
	}
	tw.Flush()
	fmt.Printf("\nUDP: ответили %d, возможно открыты (без ответа) %d.\n", open, len(shown)-open)
}

// printWeb renders the web fingerprint of each open HTTP port.
func printWeb(web []WebInfo) {
	if len(web) == 0 {
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "\nВеб-сервисы\n\nПОРТ\tКОД\tSERVER\tТЕХНОЛОГИИ\tЗАГОЛОВОК\n")
	for _, w := range web {
		status := fmt.Sprint(w.Status)
		if w.Redirect != "" {
			status += " -> " + w.Redirect
		}
		fmt.Fprintf(tw, "%d/%s\t%s\t%s\t%s\t%s\n",
			w.Port, w.Scheme, status, dash(w.Server), dash(strings.Join(w.Tech, ", ")), dash(w.Title))
	}
	tw.Flush()
}

// printSubdomains renders the subdomain search as an aligned table.
func printSubdomains(sub *SubdomainResult) {
	if sub == nil {
		return
	}
	if len(sub.Wildcard) > 0 {
		fmt.Printf("\nУ зоны %s есть wildcard (*.%s -> %s) — совпадения по нему отброшены.\n",
			sub.Base, sub.Base, strings.Join(sub.Wildcard, ", "))
	}
	if len(sub.Found) == 0 {
		fmt.Printf("\nСубдоменов %s не найдено.\n", sub.Base)
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "\nСубдомены %s (%d)\n\nИМЯ\tАДРЕСА\tИСТОЧНИК\n", sub.Base, len(sub.Found))
	hijacked := 0
	for _, s := range sub.Found {
		if hasLoopback(s.Addrs) {
			hijacked++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name,
			dash(formatAddrs(s.Addrs)), strings.Join(s.Sources, ", "))
	}
	tw.Flush()
	if hijacked > 0 {
		fmt.Printf("\nИмён с адресом localhost: %d — их режет локальный DNS, реальные адреса другие.\n", hijacked)
	}
}

// formatAddrs renders an address set for the table, keeping the column narrow:
// a round-robin name can answer with a dozen addresses, and listing them all
// pushes every other column off the screen.
func formatAddrs(addrs []string) string {
	const shown = 2
	if len(addrs) <= shown {
		return strings.Join(addrs, ", ")
	}
	return fmt.Sprintf("%s +%d", strings.Join(addrs[:shown], ", "), len(addrs)-shown)
}

// hasLoopback reports whether a name resolved to localhost, which means local
// DNS filtering answered instead of the real zone.
func hasLoopback(addrs []string) bool {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
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
	noICMP := fs.Bool("no-icmp", false, "liveness by TCP/ARP only, without ICMP ping probes")
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
		return runDiscoverExpand(SplitCIDRs(*cidr), ports, *timeout, *workers, *expandDepth, *community, *scanAll, *noICMP, *asJSON)
	}

	if *allSubnets {
		return runDiscoverAll(ports, *timeout, *workers, *scanAll, *noICMP, *asJSON)
	}

	// An explicit --cidr may name several subnets; sweep them all via DiscoverLive.
	cidrs := SplitCIDRs(*cidr)
	if len(cidrs) > 1 {
		return runDiscoverCIDRs(cidrs, ports, *timeout, *workers, *scanAll, *noICMP, *asJSON)
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
		targets = filterAlive(hosts, *timeout, *workers, !*noICMP)
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
func runDiscoverAll(ports []int, timeout time.Duration, workers int, scanAll, noICMP, asJSON bool) error {
	subnets := localSubnets()
	if len(subnets) == 0 {
		return fmt.Errorf("не найдено локальных подсетей для сканирования")
	}
	if !asJSON {
		fmt.Printf("Подсети для сканирования (%d): %s\n\n", len(subnets), strings.Join(subnets, ", "))
	}

	results, err := DiscoverLive(context.Background(),
		DiscoverOptions{AllSubnets: true, Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll, NoICMP: noICMP},
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
func runDiscoverCIDRs(cidrs []string, ports []int, timeout time.Duration, workers int, scanAll, noICMP, asJSON bool) error {
	if !asJSON {
		fmt.Printf("Подсети для сканирования (%d): %s\n\n", len(cidrs), strings.Join(cidrs, ", "))
	}

	results, err := DiscoverLive(context.Background(),
		DiscoverOptions{CIDRs: cidrs, Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll, NoICMP: noICMP},
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
func runDiscoverExpand(seeds []string, ports []int, timeout time.Duration, workers, depth int, community string, scanAll, noICMP, asJSON bool) error {
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
			Ports: ports, Timeout: timeout, Workers: workers, ScanAll: scanAll, NoICMP: noICMP},
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
