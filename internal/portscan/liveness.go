package portscan

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// livenessPorts are probed to decide if a host is up. A connection that either
// succeeds or is actively refused proves the host exists; only when every probe
// times out (or is dropped) is the host treated as down.
var livenessPorts = []int{80, 443, 22, 445, 3389, 139, 53, 8080, 135}

// hostAlive returns true if the host answers an ICMP echo (when useICMP is set)
// or answers/refuses any liveness port within timeout. ICMP and TCP race: many
// hosts silently drop TCP but still reply to a ping, and vice versa.
func hostAlive(host string, timeout time.Duration, useICMP bool) bool {
	probes := len(livenessPorts)
	if useICMP {
		probes++
	}
	ch := make(chan bool, probes)

	if useICMP {
		go func() { ch <- icmpAlive(host, timeout) }()
	}
	for _, p := range livenessPorts {
		go func(port int) {
			addr := net.JoinHostPort(host, fmt.Sprint(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				ch <- true
				return
			}
			ch <- isRefused(err) // refused == host is up
		}(p)
	}
	for range probes {
		if <-ch {
			return true
		}
	}
	return false
}

// isRefused reports whether a dial error is a TCP RST (connection refused),
// which means the host is reachable but the port is closed.
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

// filterAlive returns the hosts that are up, in input order. It combines three
// signals: the system ARP cache (an L2 neighbour exists), ICMP echo, and the
// TCP liveness ports. The ARP cache is read again afterwards because the probes
// themselves resolve addresses — a host that answers ARP but drops every IP
// probe is still provably present on the subnet.
func filterAlive(hosts []string, timeout time.Duration, workers int, useICMP bool) []string {
	if workers < 1 {
		workers = 1
	}
	alive := arpNeighbors(hosts)

	var pending []string
	for _, h := range hosts {
		if !alive[h] {
			pending = append(pending, h)
		}
	}

	type res struct {
		host  string
		alive bool
	}
	sem := make(chan struct{}, workers)
	out := make(chan res, len(pending))

	for _, h := range pending {
		sem <- struct{}{}
		go func(host string) {
			defer func() { <-sem }()
			out <- res{host, hostAlive(host, timeout, useICMP)}
		}(h)
	}
	for range pending {
		if r := <-out; r.alive {
			alive[r.host] = true
		}
	}

	for h := range arpNeighbors(hosts) {
		alive[h] = true
	}

	ordered := make([]string, 0, len(alive))
	for _, h := range hosts {
		if alive[h] {
			ordered = append(ordered, h)
		}
	}
	return ordered
}

// arpNeighbors returns the subset of hosts that the system ARP cache maps to a
// real unicast MAC — proof of an L2 neighbour regardless of IP-level filtering.
func arpNeighbors(hosts []string) map[string]bool {
	table := arpTable()
	if len(table) == 0 {
		return map[string]bool{}
	}
	found := map[string]bool{}
	for _, h := range hosts {
		if mac, ok := table[h]; ok && isUnicastMAC(mac) {
			found[h] = true
		}
	}
	return found
}

// isUnicastMAC rejects the broadcast address and the multicast range (the
// least-significant bit of the first octet is the group bit), which the ARP
// cache lists as static entries for addresses no host actually owns.
func isUnicastMAC(mac string) bool {
	if mac == "" || mac == "ff:ff:ff:ff:ff:ff" {
		return false
	}
	var first byte
	if _, err := fmt.Sscanf(mac[:2], "%02x", &first); err != nil {
		return false
	}
	return first&1 == 0
}
