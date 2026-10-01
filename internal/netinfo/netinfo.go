// Package netinfo reports local and external network configuration: external
// IP/ISP (via a public API), local interfaces with their IP/MAC addresses,
// the default gateway, the system's configured DNS servers, and whether IPv6
// is available. Gateway/DNS discovery is OS-specific (see netinfo_linux.go,
// netinfo_darwin.go, netinfo_windows.go); this file holds the shared result
// type and the pure text parsers so they can be unit tested on any platform.
package netinfo

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"speedtest/internal/util"
)

// IfaceInfo describes one local network interface.
type IfaceInfo struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// Result is the full network info snapshot (--json).
type Result struct {
	ExternalIP  string      `json:"external_ip,omitempty"`
	ISP         string      `json:"isp,omitempty"`
	City        string      `json:"city,omitempty"`
	Country     string      `json:"country,omitempty"`
	ExternalErr string      `json:"external_error,omitempty"`
	Interfaces  []IfaceInfo `json:"interfaces"`
	Gateway     string      `json:"gateway,omitempty"`
	GatewayErr  string      `json:"gateway_error,omitempty"`
	DNSServers  []string    `json:"dns_servers,omitempty"`
	DNSErr      string      `json:"dns_error,omitempty"`
	IPv6        bool        `json:"ipv6_supported"`
}

// ipAPIResponse is the shape of http://ip-api.com/json/.
type ipAPIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Query   string `json:"query"`
	ISP     string `json:"isp"`
	City    string `json:"city"`
	Country string `json:"country"`
}

// defaultGateway and systemDNS are implemented per-OS (netinfo_linux.go,
// netinfo_darwin.go, netinfo_windows.go).

// Gather collects everything RunInfo reports. Individual sub-lookups that
// fail (no internet, platform command missing, ...) are recorded as *Err
// fields rather than aborting the whole snapshot — local-only info is still
// useful when offline.
func Gather(ctx context.Context) Result {
	var res Result

	if ip, isp, city, country, err := externalInfo(ctx); err != nil {
		res.ExternalErr = err.Error()
	} else {
		res.ExternalIP, res.ISP, res.City, res.Country = ip, isp, city, country
	}

	res.Interfaces = localInterfaces()
	res.IPv6 = hasIPv6(res.Interfaces)

	if gw, err := defaultGateway(); err != nil {
		res.GatewayErr = err.Error()
	} else {
		res.Gateway = gw
	}

	if dns, err := systemDNS(); err != nil {
		res.DNSErr = err.Error()
	} else {
		res.DNSServers = dns
	}

	return res
}

// externalInfo queries the public IP/ISP lookup API.
func externalInfo(ctx context.Context) (ip, isp, city, country string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/", nil)
	if err != nil {
		return "", "", "", "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("запрос внешнего IP: %w", err)
	}
	defer resp.Body.Close()

	var r ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", "", "", fmt.Errorf("разбор ответа: %w", err)
	}
	if r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = "неизвестная ошибка"
		}
		return "", "", "", "", fmt.Errorf("%s", msg)
	}
	return r.Query, r.ISP, r.City, r.Country, nil
}

// localInterfaces lists up, non-loopback interfaces with their MAC and IPs.
func localInterfaces() []IfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []IfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		info := IfaceInfo{Name: iface.Name, MAC: iface.HardwareAddr.String()}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				info.IPs = append(info.IPs, ipNet.IP.String())
			}
		}
		if len(info.IPs) == 0 {
			continue
		}
		out = append(out, info)
	}
	return out
}

// hasIPv6 reports whether any interface holds a non-loopback IPv6 address.
func hasIPv6(ifaces []IfaceInfo) bool {
	for _, iface := range ifaces {
		for _, s := range iface.IPs {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() != nil {
				continue
			}
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			return true
		}
	}
	return false
}

// parseProcNetRoute extracts the default-route gateway from the contents of
// Linux's /proc/net/route (hex, little-endian).
func parseProcNetRoute(s string) (string, error) {
	lines := strings.Split(s, "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" { // Destination
			continue
		}
		gwHex := fields[2]
		if len(gwHex) != 8 {
			continue
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			var v int
			if _, err := fmt.Sscanf(gwHex[i*2:i*2+2], "%02x", &v); err != nil {
				return "", fmt.Errorf("разбор шлюза: %w", err)
			}
			b[3-i] = byte(v)
		}
		return net.IP(b[:]).String(), nil
	}
	return "", fmt.Errorf("маршрут по умолчанию не найден")
}

// parseResolvConf extracts nameserver addresses from /etc/resolv.conf text
// (Linux and macOS share this format).
func parseResolvConf(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out = append(out, fields[1])
		}
	}
	return out
}

// parseDarwinRouteGet extracts the gateway line from `route -n get default`.
func parseDarwinRouteGet(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}

// winRouteDefaultRe matches the IPv4 default-route row of `route print -4`:
// "0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.23    25"
var winRouteDefaultRe = regexp.MustCompile(`(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})`)

// parseWindowsRoutePrint extracts the default gateway from `route print -4`.
func parseWindowsRoutePrint(s string) string {
	m := winRouteDefaultRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// parseWindowsDNS extracts DNS server addresses from `ipconfig /all`: a "DNS
// Servers" label followed by an IP, and any further indented IP-only lines
// that continue the same list.
func parseWindowsDNS(s string) []string {
	var out []string
	inList := false
	ipOnlyRe := regexp.MustCompile(`^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)\s*$`)
	for _, line := range strings.Split(s, "\n") {
		if idx := strings.Index(line, "DNS Servers"); idx >= 0 {
			if ci := strings.Index(line, ":"); ci >= 0 {
				v := strings.TrimSpace(line[ci+1:])
				if v != "" {
					out = append(out, v)
				}
			}
			inList = true
			continue
		}
		if inList {
			if m := ipOnlyRe.FindStringSubmatch(line); m != nil {
				out = append(out, m[1])
				continue
			}
			inList = false
		}
	}
	return out
}

// RunInfo is the CLI entry point for `speedtest info`.
func RunInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output result as JSON")
	if _, err := util.ParseFlags(fs, args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res := Gather(ctx)

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Println("Внешний IP:")
	if res.ExternalErr != "" {
		fmt.Printf("  недоступно: %s\n", res.ExternalErr)
	} else {
		fmt.Printf("  %s  (%s, %s, %s)\n", res.ExternalIP, res.ISP, res.City, res.Country)
	}

	fmt.Println("\nЛокальные интерфейсы:")
	if len(res.Interfaces) == 0 {
		fmt.Println("  не найдено")
	}
	for _, i := range res.Interfaces {
		fmt.Printf("  %-12s MAC %-17s IP %s\n", i.Name, i.MAC, strings.Join(i.IPs, ", "))
	}

	fmt.Println("\nШлюз по умолчанию:")
	if res.GatewayErr != "" {
		fmt.Printf("  недоступно: %s\n", res.GatewayErr)
	} else {
		fmt.Printf("  %s\n", res.Gateway)
	}

	fmt.Println("\nDNS-серверы:")
	if res.DNSErr != "" {
		fmt.Printf("  недоступно: %s\n", res.DNSErr)
	} else if len(res.DNSServers) == 0 {
		fmt.Println("  не найдено")
	} else {
		fmt.Printf("  %s\n", strings.Join(res.DNSServers, ", "))
	}

	fmt.Println("\nIPv6:")
	if res.IPv6 {
		fmt.Println("  поддерживается")
	} else {
		fmt.Println("  не обнаружен")
	}
	return nil
}
