package portscan

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// ouiVendors maps an IEEE OUI prefix (first 3 MAC bytes, uppercase hex, no
// separators) to a vendor name. This is a small curated subset of the full
// IEEE registry covering the devices most common on home/office LANs.
var ouiVendors = map[string]string{
	"001451": "Apple", "0016CB": "Apple", "001EC2": "Apple", "0023DF": "Apple",
	"0025BC": "Apple", "3C0754": "Apple", "A85C2C": "Apple", "F0DBF8": "Apple",
	"AC87A3": "Apple", "D0817A": "Apple", "F80377": "Apple", "84FCFE": "Apple",
	"001632": "Samsung", "0021D1": "Samsung", "0023D7": "Samsung", "5001BB": "Samsung",
	"8425DB": "Samsung", "C8BA94": "Samsung", "E8508B": "Samsung", "F008F1": "Samsung",
	"001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google", "F88FCA": "Google",
	"D8EB97": "Intel", "3C970E": "Intel", "A0C589": "Intel", "48513B": "Intel",
	"001B21": "Intel", "001CC0": "Intel", "0021CC": "Intel", "7CB27D": "Intel",
	"000C29": "VMware", "005056": "VMware", "001C14": "VMware",
	"080027": "VirtualBox",
	"001A2B": "Cisco", "00259C": "Cisco", "0026CB": "Cisco", "F09E63": "Cisco",
	"5CE0C5": "Cisco", "70DB98": "Cisco",
	"14CC20": "TP-Link", "50C7BF": "TP-Link", "6466B3": "TP-Link", "A42BB0": "TP-Link",
	"C46E1F": "TP-Link", "F4F26D": "TP-Link", "EC086B": "TP-Link",
	"001882": "Huawei", "00259E": "Huawei", "48DB50": "Huawei", "80B686": "Huawei",
	"E0247F": "Huawei", "F4C714": "Huawei",
	"286C07": "Xiaomi", "3480B3": "Xiaomi", "640980": "Xiaomi", "7451BA": "Xiaomi",
	"98FAE3": "Xiaomi", "F48B32": "Xiaomi",
	"001D0F": "TP-Link", "00904C": "Epson", "AC1826": "Hikvision",
	"0004F2": "Polycom", "001217": "Cisco-Linksys", "00223F": "Netgear",
	"20E52A": "Netgear", "A040A0": "Netgear", "3894ED": "Routerboard/MikroTik",
	"6C3B6B": "MikroTik", "48A98A": "MikroTik", "CC2DE0": "MikroTik",
	"DCA632": "RaspberryPi", "B827EB": "RaspberryPi", "E45F01": "RaspberryPi",
	"2CCF67": "RaspberryPi",
	"001788": "Philips-Hue", "ECFABC": "Amazon", "FCA667": "Amazon", "44650D": "Amazon",
	"0017A0": "Sony", "FCF152": "Sony", "001315": "Sony",
	"D46A6A": "Liteon", "701A04": "Liteon",
	// Common on office LANs / infrastructure.
	"C074AD": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti", "44D9E7": "Ubiquiti",
	"000B82": "Grandstream", "000AF7": "Broadcom", "0003FD": "Cisco", "00E04C": "Realtek",
	"525400": "QEMU/KVM", "000C42": "Routerboard/MikroTik",
}

// ouiOnce guards the one-time load of an external OUI database.
var ouiOnce sync.Once

// vendorForMAC returns the vendor for a MAC address, or "" if unknown.
// Accepts common separators (":", "-") and mixed case. On first use it merges
// an external OUI database if the SPEEDTEST_OUI environment variable points to
// one (Wireshark `manuf` or Nmap `nmap-mac-prefixes` format), giving full
// vendor coverage without bundling the multi-MB IEEE registry.
func vendorForMAC(mac string) string {
	ouiOnce.Do(loadExternalOUI)
	clean := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(clean) < 6 {
		return ""
	}
	return ouiVendors[clean[:6]]
}

// loadExternalOUI merges the file named by SPEEDTEST_OUI into ouiVendors, if set
// and readable. Built-in entries are not overwritten. Best-effort: any error is
// silently ignored so a missing/garbled file never breaks a scan.
func loadExternalOUI() {
	path := os.Getenv("SPEEDTEST_OUI")
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		prefix, vendor, ok := parseOUILine(sc.Text())
		if ok {
			if _, exists := ouiVendors[prefix]; !exists {
				ouiVendors[prefix] = vendor
			}
		}
	}
	_ = sc.Err() // best-effort: a truncated file still contributes its good lines
}

// parseOUILine parses one line of a Wireshark `manuf` (tab-separated:
// prefix, short, long) or Nmap `nmap-mac-prefixes` (prefix + space + vendor)
// database. It returns the 6-hex OUI prefix and the most descriptive vendor
// name. Lines with a mask length other than 24 bits, comments and blanks are
// rejected (ok=false).
func parseOUILine(line string) (prefix, vendor string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	// The first whitespace/tab-delimited token is the prefix (maybe with /len).
	tok := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(tok) < 2 {
		return "", "", false
	}
	raw := tok[0]
	if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		if raw[slash+1:] != "24" { // only full 24-bit OUIs map to a 3-byte key
			return "", "", false
		}
		raw = raw[:slash]
	}
	clean := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(raw))
	if len(clean) < 6 {
		return "", "", false
	}
	// Vendor = everything after the prefix token; prefer the long name (the last
	// tab-separated field in manuf) when present.
	rest := strings.TrimSpace(line[len(tok[0]):])
	if i := strings.LastIndexByte(rest, '\t'); i >= 0 {
		rest = strings.TrimSpace(rest[i+1:])
	}
	if rest == "" {
		return "", "", false
	}
	return clean[:6], rest, true
}
