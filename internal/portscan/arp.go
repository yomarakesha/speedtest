package portscan

import (
	"os/exec"
	"regexp"
	"strings"
)

// macRe matches both Windows ("00-11-22-33-44-55") and Unix
// ("00:11:22:33:44:55") MAC formats.
var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)

// ipRe matches an IPv4 address.
var ipRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// arpTable reads the system ARP cache and returns ip -> MAC (normalized to
// colon-separated lowercase). Best-effort: returns an empty map on any error.
func arpTable() map[string]string {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return map[string]string{}
	}
	return parseARP(string(out))
}

// parseARP extracts ip->mac pairs from `arp -a` output on Windows/Linux/macOS.
func parseARP(s string) map[string]string {
	table := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		mac := macRe.FindString(line)
		if mac == "" {
			continue
		}
		ip := ipRe.FindString(line)
		if ip == "" {
			continue
		}
		table[ip] = normalizeMAC(mac)
	}
	return table
}

// normalizeMAC converts any accepted separator to ":" and lowercases the hex.
func normalizeMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
}
