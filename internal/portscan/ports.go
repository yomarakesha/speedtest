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
	554: "rtsp", 1194: "openvpn", 1900: "ssdp", 1935: "rtmp", 4500: "ipsec-nat",
	5222: "xmpp", 5683: "coap", 5985: "winrm", 5986: "winrm-s", 6568: "anydesk",
	5938: "teamviewer", 7000: "cassandra", 8009: "ajp/cast", 8086: "influxdb",
	8096: "jellyfin", 8883: "mqtts", 9042: "cassandra", 9100: "jetdirect",
	9443: "https-alt", 25565: "minecraft", 27015: "steam", 37777: "dahua",
	51820: "wireguard", 49152: "upnp", 2375: "docker", 2376: "docker-tls",
	6443: "kubernetes", 10250: "kubelet", 5601: "kibana", 15672: "rabbitmq",
	5672: "amqp", 9092: "kafka", 2181: "zookeeper", 873: "rsync", 3128: "squid",
}

// defaultDiscoverPorts is the compact set scanned during subnet discovery.
var defaultDiscoverPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
	1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017,
}

// serviceName returns the service label for a port, or "" if unknown.
func serviceName(p int) string { return commonServices[p] }

// ServiceName is the exported form of serviceName for UI callers.
func ServiceName(p int) string { return commonServices[p] }

// ParsePorts is the exported form of parsePorts for UI callers.
func ParsePorts(spec string) ([]int, error) { return parsePorts(spec) }

// DefaultDiscoverPorts returns a copy of the compact discovery port set.
func DefaultDiscoverPorts() []int {
	out := make([]int, len(defaultDiscoverPorts))
	copy(out, defaultDiscoverPorts)
	return out
}

// portPresets are named port sets usable anywhere a port spec is accepted, and
// freely mixable with numbers: "common,8000-8100", "all".
var portPresets = map[string]string{
	"all":       "1-65535",
	"known":     "1-1024",
	"web":       "80,81,443,591,2082,2083,2086,2087,3000,4443,5000,7080,7443,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443",
	"db":        "1433,1521,3306,5432,5984,6379,7000,7001,8086,9042,9200,11211,27017,28015",
	"remote":    "22,23,2222,3389,5800,5900,5901,5938,6568",
	"iot":       "23,80,443,554,1883,1900,5000,5683,8080,8883,9999,37777,49152",
	"windows":   "135,137,139,445,3389,5985,5986",
	"mail":      "25,110,143,465,587,993,995",
	"media":     "554,1935,5004,8008,8009,8096,8200,32400",
	"printer":   "515,631,9100",
	"games":     "3074,3478,3479,25565,27015,27016,27036,7777,19132",
	"vpn":       "500,1194,1701,1723,4500,51820",
	"common":    "", // filled in init from commonServices
	"discovery": "", // filled in init from defaultDiscoverPorts
}

func init() {
	var common, disc []string
	for p := range commonServices {
		common = append(common, strconv.Itoa(p))
	}
	for _, p := range defaultDiscoverPorts {
		disc = append(disc, strconv.Itoa(p))
	}
	portPresets["common"] = strings.Join(common, ",")
	portPresets["discovery"] = strings.Join(disc, ",")
}

// PresetNames returns the available preset names, sorted.
func PresetNames() []string {
	out := make([]string, 0, len(portPresets))
	for k := range portPresets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parsePorts expands a spec like "22,80,443", "1-1024", "1-100,3389,8000-8100"
// or a preset name ("all", "common", "web", ...) into a sorted, de-duplicated
// slice of port numbers.
func parsePorts(spec string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if preset, ok := portPresets[strings.ToLower(part)]; ok {
			sub, err := parsePorts(preset)
			if err != nil {
				return nil, err
			}
			for _, p := range sub {
				seen[p] = struct{}{}
			}
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
