package portscan

import "strings"

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
	"001D0F": "TP-Link", "00904C": "Epson", "AC18261": "Hikvision",
	"0004F2": "Polycom", "001217": "Cisco-Linksys", "00223F": "Netgear",
	"20E52A": "Netgear", "A040A0": "Netgear", "3894ED": "Routerboard/MikroTik",
	"6C3B6B": "MikroTik", "48A98A": "MikroTik", "CC2DE0": "MikroTik",
	"DCA632": "RaspberryPi", "B827EB": "RaspberryPi", "E45F01": "RaspberryPi",
	"2CCF67": "RaspberryPi",
	"001788": "Philips-Hue", "ECFABC": "Amazon", "FCA667": "Amazon", "44650D": "Amazon",
	"0017A0": "Sony", "FCF152": "Sony", "001315": "Sony",
	"D46A6A": "Liteon", "701A04": "Liteon",
}

// vendorForMAC returns the vendor for a MAC address, or "" if unknown.
// Accepts common separators (":", "-") and mixed case.
func vendorForMAC(mac string) string {
	clean := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(clean) < 6 {
		return ""
	}
	return ouiVendors[clean[:6]]
}
