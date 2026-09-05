package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"speedtest/internal/trace"
)

// Subnet auto-discovery ("expand"): a breadth-first sweep that grows the set of
// subnets it scans by asking the network where the other subnets are, instead of
// trusting only the local machine's routing table. Two signals feed it:
//
//   - SNMP: each subnet's likely gateway (.1/.254) is walked for its interface
//     table (ipAddrTable), revealing every subnet that router bridges — including
//     ones with no route on this host. Requires a community string.
//   - traceroute: a single-pass trace to a live host in each subnet exposes the
//     transit routers on the path; each router interface hints at a subnet
//     (assumed /24 — SNMP refines it later if reachable).
//
// New subnets are queued and scanned recursively up to MaxDepth. Everything is
// read-only and best-effort; unreachable gateways and closed SNMP agents simply
// contribute nothing.

// ExpandOptions configures a recursive subnet-discovery sweep.
type ExpandOptions struct {
	Seeds      []string      // starting subnets; empty => localSubnets()
	MaxDepth   int           // expansion rounds beyond the seeds (default 2)
	MaxSubnets int           // hard cap on total subnets scanned (default 64)
	Community  string        // SNMP community; empty => skip the SNMP signal
	Ports      []int         // per-host ports; empty => defaultDiscoverPorts
	Timeout    time.Duration // per-probe connect/SNMP timeout
	Workers    int           // global connection budget per subnet scan
	ScanAll    bool          // skip the liveness pre-check
	NoICMP     bool          // liveness by TCP/ARP only, no ping probe
}

// ExpandResult is the outcome of an expand sweep.
type ExpandResult struct {
	Subnets []string          // every subnet scanned, sorted
	Hosts   []HostResult      // every live host found across all subnets
	Sources map[string]string // subnet => how it was discovered
}

// ExpandDiscover runs the recursive sweep. onSubnet (may be nil) fires as each
// new subnet is discovered with a short human-readable source; onHost (may be
// nil) fires per live host, same as DiscoverLive. It returns the combined result.
func ExpandDiscover(ctx context.Context, opt ExpandOptions,
	onSubnet func(cidr, source string), onHost func(HostResult)) (ExpandResult, error) {

	if opt.MaxDepth <= 0 {
		opt.MaxDepth = 2
	}
	if opt.MaxSubnets <= 0 {
		opt.MaxSubnets = 64
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 500 * time.Millisecond
	}
	if opt.Workers < 1 {
		opt.Workers = 500
	}

	seeds := opt.Seeds
	if len(seeds) == 0 {
		seeds = localSubnets()
		if len(seeds) == 0 {
			return ExpandResult{}, errNoSubnets
		}
	}

	res := ExpandResult{Sources: map[string]string{}}
	known := map[string]bool{}
	var knownNets []*net.IPNet
	var queue []string
	enqueue := func(cidr, source string) {
		if cidr == "" || known[cidr] || len(known) >= opt.MaxSubnets {
			return
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return
		}
		if _, err := hostsInCIDR(cidr); err != nil {
			return // too large / malformed
		}
		if coveredBy(ipnet, knownNets) {
			return // already inside a broader subnet we will scan — skip the subset
		}
		known[cidr] = true
		knownNets = append(knownNets, ipnet)
		queue = append(queue, cidr)
		res.Subnets = append(res.Subnets, cidr)
		res.Sources[cidr] = source
		if onSubnet != nil {
			onSubnet(cidr, source)
		}
	}
	for _, s := range seeds {
		enqueue(s, "локальная")
	}

	scanOpt := DiscoverOptions{Ports: opt.Ports, Timeout: opt.Timeout, Workers: opt.Workers, ScanAll: opt.ScanAll, NoICMP: opt.NoICMP}
	for depth := 0; depth <= opt.MaxDepth; depth++ {
		frontier := queue
		queue = nil
		for _, cidr := range frontier {
			if ctx.Err() != nil {
				return finalize(res), ctx.Err()
			}
			hosts, err := discoverSubnet(ctx, cidr, scanOpt, nil, onHost)
			if err != nil {
				continue // unreachable/unscannable subnet — skip, keep going
			}
			res.Hosts = append(res.Hosts, hosts...)
			if depth == opt.MaxDepth {
				continue // last round: scan only, don't expand further
			}
			for cand, src := range discoverNeighbors(ctx, cidr, hosts, opt) {
				enqueue(cand, src)
			}
		}
		if len(queue) == 0 {
			break
		}
	}
	return finalize(res), nil
}

// discoverNeighbors asks the network for subnets adjacent to cidr, returning
// candidate CIDR => source. It probes the subnet's gateways over SNMP (when a
// community is set) and traces to a live host to expose transit routers.
func discoverNeighbors(ctx context.Context, cidr string, hosts []HostResult, opt ExpandOptions) map[string]string {
	out := map[string]string{}

	// SNMP: walk the likely gateways' interface tables.
	if opt.Community != "" {
		for _, gw := range routerGuesses(cidr) {
			for _, sub := range snmpSubnets(gw, opt.Community, opt.Timeout) {
				out[sub] = "SNMP через " + gw
			}
		}
	}

	// Traceroute: to a live host (routers on the path reveal transit subnets).
	if target := traceTarget(cidr, hosts); target != "" {
		hops, err := trace.TraceOnce(ctx, trace.Options{Host: target, MaxHops: 20, Timeout: opt.Timeout})
		if err == nil {
			for _, h := range hops {
				if sub := hopSubnet(h.Host); sub != "" {
					if _, ok := out[sub]; !ok {
						out[sub] = "traceroute к " + target
					}
				}
			}
		}
	}
	return out
}

// traceTarget picks a host to trace toward: prefer a live host that is not an
// obvious gateway (so the trace crosses real transit), else the first gateway
// guess. Returns "" when nothing is reachable.
func traceTarget(cidr string, hosts []HostResult) string {
	gws := map[string]bool{}
	for _, g := range routerGuesses(cidr) {
		gws[g] = true
	}
	for _, h := range hosts {
		if len(h.Open) > 0 && !gws[h.IP] {
			return h.IP
		}
	}
	for _, h := range hosts {
		return h.IP
	}
	for _, g := range routerGuesses(cidr) {
		return g
	}
	return ""
}

// hopSubnet maps a traceroute hop IP to its assumed /24 subnet, or "" for a
// timed-out hop or a non-LAN address. The real prefix is unknown from a trace;
// /24 is the common LAN case and SNMP refines it if the gateway answers.
func hopSubnet(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	cidr := fmt.Sprintf("%d.%d.%d.0/24", p[0], p[1], p[2])
	if !usefulSubnet(cidr) {
		return ""
	}
	return cidr
}

// coveredBy reports whether every address of sub already falls inside one of the
// nets (i.e. sub is that net or a subset of it), so scanning sub would be
// redundant. It compares network base and prefix length.
func coveredBy(sub *net.IPNet, nets []*net.IPNet) bool {
	subOnes, _ := sub.Mask.Size()
	for _, n := range nets {
		ones, _ := n.Mask.Size()
		if ones <= subOnes && n.Contains(sub.IP) {
			return true
		}
	}
	return false
}

// finalize sorts the subnets, then deduplicates and sorts the host list —
// overlapping subnets (a /24 hint inside a /22 seed) can surface the same host
// more than once.
func finalize(res ExpandResult) ExpandResult {
	sort.Strings(res.Subnets)
	sortResultsByIP(res.Hosts)
	seen := map[string]bool{}
	deduped := make([]HostResult, 0, len(res.Hosts))
	for _, h := range res.Hosts {
		if seen[h.IP] {
			continue
		}
		seen[h.IP] = true
		deduped = append(deduped, h)
	}
	res.Hosts = deduped
	return res
}
