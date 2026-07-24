package portscan

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// reverseDNS returns the first PTR hostname for ip, or "" if none resolves
// within the timeout. Bounded so a slow resolver can't stall a scan.
func reverseDNS(ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// localCIDR returns the network (in CIDR form, e.g. "192.168.1.0/24") of the
// interface the OS would actually use to reach the internet. This avoids
// picking a Docker/WSL/VPN virtual adapter over the real LAN NIC.
func localCIDR() (string, error) {
	src, err := preferredSourceIP()
	if err != nil {
		return "", err
	}
	// Find the interface address that owns src to learn its netmask.
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipnet.IP.To4(); ip4 != nil && ip4.Equal(src) {
				return (&net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}).String(), nil
			}
		}
	}
	// Fall back to a /24 around the source IP if the mask can't be found.
	return src.Mask(net.CIDRMask(24, 32)).String() + "/24", nil
}

// preferredSourceIP asks the OS which local IPv4 it would use to reach a
// public address. No packets are sent (UDP connect just sets up routing).
func preferredSourceIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("нет IPv4-маршрута в интернет")
	}
	return ip, nil
}

// SplitCIDRs parses a comma/space/tab-separated list of CIDRs into a trimmed,
// order-preserving, deduplicated slice. Empty entries are dropped. Lets a UI or
// CLI accept several subnets in one field, e.g. "192.168.20.0/24, 10.0.0.0/24".
func SplitCIDRs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// hostsInCIDR returns every usable host address in a CIDR block. For blocks
// larger than /16 it returns an error to avoid runaway scans.
func hostsInCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("некорректный CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("подсеть %s слишком большая (>65534 хостов); сузьте её", cidr)
	}

	var hosts []string
	ip := ipnet.IP.Mask(ipnet.Mask).To4()
	if ip == nil {
		return nil, fmt.Errorf("поддерживаются только IPv4-подсети")
	}
	for cur := cloneIP(ip); ipnet.Contains(cur); incIP(cur) {
		hosts = append(hosts, cur.String())
	}
	// Drop network and broadcast addresses for prefixes shorter than /31.
	if bits-ones >= 2 && len(hosts) >= 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

// IfaceInfo describes one up, non-loopback interface and an IPv4 subnet it owns.
type IfaceInfo struct {
	Name string
	IP   string
	CIDR string
}

// localInterfaces returns every usable IPv4 subnet the machine is directly
// attached to, one entry per interface address. Down, loopback, link-local and
// non-IPv4 addresses are skipped.
func localInterfaces() []IfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []IfaceInfo
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() {
				continue
			}
			cidr := (&net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
			out = append(out, IfaceInfo{Name: ifi.Name, IP: ip4.String(), CIDR: cidr})
		}
	}
	return out
}

// localSubnets returns the deduplicated set of IPv4 subnets worth sweeping:
// every directly-attached interface subnet plus any extra on-link subnets from
// the routing table (other VLANs / interfaces). Each is capped at /16 by
// hostsInCIDR; the result is sorted for stable output.
func localSubnets() []string {
	seen := map[string]bool{}
	var out []string
	add := func(cidr string) {
		if cidr == "" || seen[cidr] {
			return
		}
		if _, err := hostsInCIDR(cidr); err != nil {
			return // too large, non-IPv4, or malformed
		}
		seen[cidr] = true
		out = append(out, cidr)
	}
	for _, ifi := range localInterfaces() {
		add(ifi.CIDR)
	}
	for _, cidr := range routedSubnets() {
		add(cidr)
	}
	sort.Strings(out)
	return out
}

// routedSubnets parses the OS routing table for extra on-link IPv4 subnets.
// Best-effort: returns nil if the routing tool is missing or output can't be
// parsed, in which case callers fall back to interface subnets alone.
func routedSubnets() []string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("route", "print", "-4")
	case "linux":
		cmd = exec.Command("ip", "-4", "route")
	default:
		return nil // macOS/BSD netstat output is abbreviated; skip
	}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseRoutes(string(out), runtime.GOOS)
}

// parseRoutes extracts candidate IPv4 subnet CIDRs from routing-table output.
// Windows rows are "dest netmask gateway iface metric"; Linux `ip route` rows
// begin with a CIDR (or "default"). Uninteresting routes are dropped.
func parseRoutes(text, goos string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var cidr string
		if goos == "windows" {
			cidr = routeToCIDR(f[0], f[1])
		} else if strings.Contains(f[0], "/") {
			cidr = f[0]
		}
		if usefulSubnet(cidr) {
			out = append(out, cidr)
		}
	}
	return out
}

// routeToCIDR turns a dotted destination + dotted netmask into a CIDR string,
// or "" if either is not a valid IPv4 address/mask.
func routeToCIDR(dest, mask string) string {
	dip := net.ParseIP(dest).To4()
	mip := net.ParseIP(mask).To4()
	if dip == nil || mip == nil {
		return ""
	}
	m := net.IPMask(mip)
	ones, bits := m.Size()
	if bits != 32 { // non-contiguous mask
		return ""
	}
	return fmt.Sprintf("%s/%d", dip.Mask(m).String(), ones)
}

// usefulSubnet reports whether a CIDR is a real, scannable LAN subnet (not a
// default route, host route, loopback, link-local or multicast block).
func usefulSubnet(cidr string) bool {
	if cidr == "" {
		return false
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	if ones == 0 || ones >= 31 { // default route or host route
		return false
	}
	if ip4[0] == 127 || ip4[0] >= 224 || (ip4[0] == 169 && ip4[1] == 254) {
		return false
	}
	return true
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func decIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]--
		if ip[i] != 0xff {
			break
		}
	}
}

// routerGuesses returns the two addresses most likely to be the gateway of a
// subnet: the first host (network+1, e.g. .1) and the last host (broadcast-1,
// e.g. .254). Used as SNMP probe targets during --expand. Returns nil for
// prefixes too small to hold hosts.
func routerGuesses(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	base := ipnet.IP.Mask(ipnet.Mask).To4()
	if base == nil {
		return nil
	}
	if ones, bits := ipnet.Mask.Size(); bits-ones < 2 {
		return nil
	}
	first := cloneIP(base)
	incIP(first)
	last := cloneIP(base)
	for i := range last {
		last[i] |= ^ipnet.Mask[i]
	}
	decIP(last) // broadcast-1
	return []string{first.String(), last.String()}
}
