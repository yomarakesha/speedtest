// Package capture provides passive top-talker accounting and raw SYN scanning
// via packet capture. The capture backend (gopacket + Npcap/libpcap) is an
// optional build: compile with `-tags pcap` and install Npcap (Windows) or
// libpcap (Linux). Without that, the exported entry points return
// ErrUnavailable and the CLI prints install instructions — the default build
// never depends on gopacket.
//
// Honest scope note: on a switched LAN a normal adapter only sees its own
// traffic plus broadcast/multicast, so top-talkers mostly reflects this host.
// Full visibility of other devices needs a mirror/SPAN port or a Wi-Fi adapter
// in monitor mode.
package capture

import (
	"context"
	"errors"
	"net"
	"sort"
	"time"
)

// ErrUnavailable is returned by the non-pcap build (or when no capture device
// can be opened) from every capture entry point.
var ErrUnavailable = errors.New(
	"захват пакетов недоступен: соберите с -tags pcap и установите Npcap (Windows) или libpcap (Linux)")

// Talker is one remote peer observed on the wire, with the byte/packet volume
// of all traffic involving it.
type Talker struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
}

// Device is a capture-capable network interface.
type Device struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Addrs       []string `json:"addrs,omitempty"`
}

// Options configures a TopTalkers capture run.
type Options struct {
	Iface    string        // capture device name; "" picks the first non-loopback with an address
	Top      int           // keep at most this many peers (0 = all)
	Interval time.Duration // how often to emit an updated ranking (default 1s)
	Resolve  bool          // reverse-DNS the emitted peers
}

// accumulator tallies bytes per remote IP from observed frames. Local
// addresses are excluded so the result lists peers, not this machine.
type accumulator struct {
	local map[string]bool
	byIP  map[string]*Talker
}

func newAccumulator() *accumulator {
	return &accumulator{local: localIPSet(), byIP: map[string]*Talker{}}
}

// observe credits both endpoints of a frame (the non-local, unicast ones) with
// its length, so a peer's total reflects both directions of a conversation.
func (a *accumulator) observe(srcIP, srcMAC, dstIP, dstMAC string, length int) {
	a.credit(srcIP, srcMAC, length)
	a.credit(dstIP, dstMAC, length)
}

func (a *accumulator) credit(ip, mac string, length int) {
	if ip == "" || a.local[ip] || !isRemoteUnicast(ip) {
		return
	}
	t := a.byIP[ip]
	if t == nil {
		t = &Talker{IP: ip, MAC: mac}
		a.byIP[ip] = t
	}
	t.Bytes += uint64(length)
	t.Packets++
	if t.MAC == "" && mac != "" {
		t.MAC = mac
	}
}

// top returns the highest-volume peers, optionally resolving reverse DNS.
func (a *accumulator) top(n int, resolve bool, timeout time.Duration) []Talker {
	list := make([]Talker, 0, len(a.byIP))
	for _, t := range a.byIP {
		list = append(list, *t)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Bytes != list[j].Bytes {
			return list[i].Bytes > list[j].Bytes
		}
		return list[i].IP < list[j].IP
	})
	if n > 0 && len(list) > n {
		list = list[:n]
	}
	if resolve {
		for i := range list {
			list[i].Hostname = reverseDNS(list[i].IP, timeout)
		}
	}
	return list
}

// localIPSet returns this machine's own IPv4/IPv6 addresses, so they can be
// excluded from the peer list.
func localIPSet() map[string]bool {
	set := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return set
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				set[ipnet.IP.String()] = true
			}
		}
	}
	return set
}

// isRemoteUnicast reports whether ip is a routable unicast peer worth counting
// (not loopback, multicast, link-local or the all-ones broadcast).
func isRemoteUnicast(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.IsLoopback() || p.IsMulticast() || p.IsLinkLocalUnicast() || p.IsUnspecified() {
		return false
	}
	if p.Equal(net.IPv4bcast) {
		return false
	}
	return true
}

// reverseDNS returns the first PTR name for ip within timeout, or "".
func reverseDNS(ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}
