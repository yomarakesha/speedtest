package portscan

import (
	"context"
	"fmt"
	"net"
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
