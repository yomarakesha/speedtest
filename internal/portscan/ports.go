package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// commonServices maps well-known ports to a short service name for display.
var commonServices = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
	110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios",
	139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
	445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 515: "printer",
	548: "afp", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
	995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
	1883: "mqtt", 2049: "nfs", 2222: "ssh-alt", 3000: "dev-http", 3306: "mysql",
	3389: "rdp", 5000: "upnp", 5060: "sip", 5432: "postgres", 5900: "vnc",
	5901: "vnc-1", 6379: "redis", 8000: "http-alt", 8008: "http-alt",
	8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
	9000: "http-alt", 9090: "http-alt", 9200: "elastic", 11211: "memcached",
	27017: "mongodb", 5353: "mdns", 32400: "plex", 62078: "iphone-sync",
}

// defaultDiscoverPorts is the compact set scanned during subnet discovery.
var defaultDiscoverPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
	1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017,
}

// serviceName returns the service label for a port, or "" if unknown.
func serviceName(p int) string { return commonServices[p] }

// parsePorts expands a spec like "22,80,443", "1-1024" or "1-100,3389,8000-8100"
// into a sorted, de-duplicated slice of port numbers.
func parsePorts(spec string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("некорректный диапазон портов %q", part)
			}
			b, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("некорректный диапазон портов %q", part)
			}
			if a > b {
				a, b = b, a
			}
			for p := a; p <= b; p++ {
				if validPort(p) {
					seen[p] = struct{}{}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || !validPort(p) {
				return nil, fmt.Errorf("некорректный порт %q", part)
			}
			seen[p] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("нет корректных портов в %q", spec)
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }
