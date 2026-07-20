package portscan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// errNoSubnets is returned when an all-subnets sweep finds no attached IPv4 LAN.
var errNoSubnets = errors.New("не найдено локальных подсетей для сканирования")

// ScanOptions configures a single-host streaming scan.
type ScanOptions struct {
	Host    string
	Ports   []int
	Timeout time.Duration
	Workers int
}

// ScanLive scans one host, invoking onProgress after each port completes and
// onOpen for each open port as it is found (both may be nil, both may be called
// from many goroutines). It returns the final ScanResult. Used by the TUI.
func ScanLive(ctx context.Context, opt ScanOptions, onProgress func(done, total int), onOpen func(PortInfo)) ScanResult {
	workers := opt.Workers
	if workers < 1 {
		workers = 1
	}
	total := len(opt.Ports)
	jobs := make(chan int)
	var mu sync.Mutex
	var open []int
	var done atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() == nil && scanPort(opt.Host, p, opt.Timeout) {
					mu.Lock()
					open = append(open, p)
					mu.Unlock()
					if onOpen != nil {
						onOpen(PortInfo{Port: p, Service: serviceName(p)})
					}
				}
				d := int(done.Add(1))
				if onProgress != nil {
					onProgress(d, total)
				}
			}
		}()
	}
	for _, p := range opt.Ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()

	sort.Ints(open)
	return ScanResult{
		Host:     opt.Host,
		Hostname: reverseDNS(opt.Host, time.Second),
		Open:     toPortInfos(open),
	}
}

// DiscoverOptions configures a streaming subnet discovery.
type DiscoverOptions struct {
	CIDR       string // empty => auto-detected local /24
	Ports      []int  // empty => defaultDiscoverPorts
	Timeout    time.Duration
	Workers    int
	ScanAll    bool // skip the liveness pre-check
	AllSubnets bool // sweep every directly-attached subnet, not just one
}

// DiscoverPhase names the two stages a UI can show.
type DiscoverPhase string

const (
	PhaseLiveness DiscoverPhase = "liveness"
	PhaseScan     DiscoverPhase = "scan"
)

// DiscoverLive sweeps one subnet, or every directly-attached subnet when
// opt.AllSubnets is set. onPhase reports stage progress (done/total, reset per
// subnet), onHost fires as each live host finishes its port scan (both may be
// nil). It returns the enriched results. Used by the TUI and CLI.
func DiscoverLive(ctx context.Context, opt DiscoverOptions, onPhase func(p DiscoverPhase, done, total int), onHost func(HostResult)) ([]HostResult, error) {
	var subnets []string
	if opt.AllSubnets {
		subnets = localSubnets()
		if len(subnets) == 0 {
			return nil, errNoSubnets
		}
	} else {
		network := opt.CIDR
		if network == "" {
			auto, err := localCIDR()
			if err != nil {
				return nil, err
			}
			network = auto
		}
		subnets = []string{network}
	}

	var all []HostResult
	var errs []error
	for _, network := range subnets {
		res, err := discoverSubnet(ctx, network, opt, onPhase, onHost)
		if err != nil {
			if len(subnets) == 1 {
				return nil, err
			}
			// Skip an unscannable subnet but keep sweeping the rest; remember the
			// failure so a total wipe-out isn't reported as an empty success.
			errs = append(errs, fmt.Errorf("%s: %w", network, err))
			continue
		}
		all = append(all, res...)
		if ctx.Err() != nil {
			break
		}
	}
	if len(all) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return all, nil
}

// discoverSubnet sweeps a single CIDR: liveness pre-check, then a bounded port
// scan of every live host, enriching and streaming each result.
func discoverSubnet(ctx context.Context, network string, opt DiscoverOptions, onPhase func(p DiscoverPhase, done, total int), onHost func(HostResult)) ([]HostResult, error) {
	hosts, err := hostsInCIDR(network)
	if err != nil {
		return nil, err
	}
	ports := opt.Ports
	if len(ports) == 0 {
		ports = defaultDiscoverPorts
	}
	workers := opt.Workers
	if workers < 1 {
		workers = 1
	}

	// Phase 1: liveness.
	targets := hosts
	if !opt.ScanAll {
		if onPhase != nil {
			onPhase(PhaseLiveness, 0, len(hosts))
		}
		targets = filterAlive(hosts, opt.Timeout, workers)
		if onPhase != nil {
			onPhase(PhaseLiveness, len(hosts), len(hosts))
		}
	}
	if len(targets) == 0 {
		return []HostResult{}, nil
	}

	// Phase 2: port scan of live hosts, reusing a global connection budget.
	results := make([]HostResult, len(targets))
	sem := make(chan struct{}, workers)
	var doneHosts atomic.Int64
	var wg sync.WaitGroup
	if onPhase != nil {
		onPhase(PhaseScan, 0, len(targets))
	}
	for i, h := range targets {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			var mu sync.Mutex
			var open []int
			var inner sync.WaitGroup
			for _, p := range ports {
				inner.Add(1)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					inner.Done()
					continue
				}
				go func(port int) {
					defer inner.Done()
					defer func() { <-sem }()
					if scanPort(host, port, opt.Timeout) {
						mu.Lock()
						open = append(open, port)
						mu.Unlock()
					}
				}(p)
			}
			inner.Wait()
			sort.Ints(open)
			hr := HostResult{IP: host, Open: toPortInfos(open)}
			enrichOne(&hr)
			results[i] = hr
			if onHost != nil {
				onHost(hr)
			}
			if onPhase != nil {
				onPhase(PhaseScan, int(doneHosts.Add(1)), len(targets))
			}
		}(i, h)
	}
	wg.Wait()
	return results, nil
}

// enrichOne fills identity (MAC, vendor, reverse DNS) for a single host.
func enrichOne(hr *HostResult) {
	if mac, ok := arpTable()[hr.IP]; ok {
		hr.MAC = mac
		hr.Vendor = vendorForMAC(mac)
	}
	hr.Hostname = reverseDNS(hr.IP, time.Second)
}
