// Package cvecheck matches service banners against a small bundled database of
// known-vulnerable version ranges. It is an indicative triage aid, not an
// authoritative scanner: the database is deliberately tiny and offline, so a
// clean result means "no match in this list", never "no vulnerabilities".
package cvecheck

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"speedtest/internal/portscan"
	"speedtest/internal/report"
	"speedtest/internal/util"
)

//go:embed cvedb.json
var cveDBRaw []byte

// Vuln is one database entry: product affected in [Introduced, Fixed).
type Vuln struct {
	Product     string `json:"product"`
	CVE         string `json:"cve"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

var cveDB []Vuln

func init() {
	if err := json.Unmarshal(cveDBRaw, &cveDB); err != nil {
		panic("cvecheck: bad embedded cvedb.json: " + err.Error())
	}
}

// bannerPattern captures a product name and a version from common banners such
// as "Apache/2.4.49", "nginx/1.18.0", "OpenSSH_8.2p1", "vsftpd 2.3.4".
var bannerPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+\-]*?)[ /_]v?(\d+(?:\.\d+)*[a-z]?\d*)`)

// productAliases normalizes banner product names to database keys.
var productAliases = map[string]string{
	"apache": "apache", "httpd": "apache", "apache2": "apache",
	"openssh": "openssh", "ssh": "openssh",
	"nginx":   "nginx",
	"vsftpd":  "vsftpd",
	"proftpd": "proftpd",
	"exim":    "exim",
}

// ParseBanner extracts a normalized (product, version) from a banner string.
// product is "" when nothing recognizable is found.
func ParseBanner(banner string) (product, version string) {
	for _, m := range bannerPattern.FindAllStringSubmatch(banner, -1) {
		name := strings.ToLower(m[1])
		if canon, ok := productAliases[name]; ok {
			return canon, m[2]
		}
	}
	return "", ""
}

// splitVersion turns a version like "2.4.49", "8.2p1", "1.3.5a" into numeric and
// trailing-letter components for comparison. Non-numeric suffixes (p1, a) are
// reduced to an ordering hint appended as a final element.
func splitVersion(v string) []int {
	v = strings.ToLower(strings.TrimSpace(v))
	var parts []int
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' }) {
		num := 0
		letter := 0
		i := 0
		for i < len(seg) && seg[i] >= '0' && seg[i] <= '9' {
			i++
		}
		if i > 0 {
			num, _ = strconv.Atoi(seg[:i])
		}
		// A trailing letter (e.g. "5a", "p1") orders after the bare number.
		for _, r := range seg[i:] {
			if r >= 'a' && r <= 'z' {
				letter = int(r-'a') + 1
				break
			}
		}
		parts = append(parts, num, letter)
	}
	return parts
}

// CompareVersions returns -1, 0, or 1 for a<b, a==b, a>b.
func CompareVersions(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

// affected reports whether version falls in [v.Introduced, v.Fixed).
func affected(v Vuln, version string) bool {
	if v.Introduced != "" && CompareVersions(version, v.Introduced) < 0 {
		return false
	}
	if v.Fixed != "" && CompareVersions(version, v.Fixed) >= 0 {
		return false
	}
	return true
}

// Match returns all database entries affecting product at version.
func Match(product, version string) []Vuln {
	var out []Vuln
	for _, v := range cveDB {
		if v.Product == product && affected(v, version) {
			out = append(out, v)
		}
	}
	return out
}

// Finding pairs a located service with its matched vulnerabilities.
type Finding struct {
	Port    int    `json:"port"`
	Banner  string `json:"banner"`
	Product string `json:"product"`
	Version string `json:"version"`
	Vulns   []Vuln `json:"vulns,omitempty"`
}

// defaultPorts are scanned when the user gives no --ports.
var defaultPorts = []int{21, 22, 25, 80, 443, 8080, 8443}

// RunCVECheck is the CLI entry point for `speedtest cvecheck <ip>`.
func RunCVECheck(args []string) error {
	fs := flag.NewFlagSet("cvecheck", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 3*time.Second, "per-port banner timeout")
	portsArg := fs.String("ports", "", "comma-separated ports (default: common service ports)")
	bannerArg := fs.String("banner", "", "check a literal banner string instead of scanning")
	asJSON := fs.Bool("json", false, "output result as JSON")
	wazuh := fs.Bool("wazuh", false, "emit findings to the Wazuh report log")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}

	// Offline mode: check a literal banner.
	if *bannerArg != "" {
		product, version := ParseBanner(*bannerArg)
		f := Finding{Banner: *bannerArg, Product: product, Version: version}
		if product != "" {
			f.Vulns = Match(product, version)
		}
		return output([]Finding{f}, "", *asJSON, *wazuh)
	}

	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest cvecheck <ip> | --banner \"строка\"")
	}
	host := pos[0]

	ports := defaultPorts
	if *portsArg != "" {
		ports, err = portscan.ParsePorts(*portsArg)
		if err != nil {
			return err
		}
	}

	var findings []Finding
	for _, p := range ports {
		banner := portscan.GrabBanner(host, p, *timeout)
		if banner == "" {
			continue
		}
		product, version := ParseBanner(banner)
		f := Finding{Port: p, Banner: banner, Product: product, Version: version}
		if product != "" {
			f.Vulns = Match(product, version)
		}
		findings = append(findings, f)
	}
	return output(findings, host, *asJSON, *wazuh)
}

func output(findings []Finding, host string, asJSON, wazuh bool) error {
	if wazuh {
		for _, f := range findings {
			for _, v := range f.Vulns {
				_ = report.Emit(report.Event{
					Tool:     "cvecheck",
					Target:   fmt.Sprintf("%s:%d", host, f.Port),
					Severity: report.Severity(v.Severity),
					Summary:  fmt.Sprintf("%s %s: %s", f.Product, f.Version, v.CVE),
					Data:     map[string]any{"cve": v.CVE, "product": f.Product, "version": f.Version, "banner": f.Banner},
				})
			}
		}
	}

	if asJSON {
		b, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	if len(findings) == 0 {
		fmt.Println("Баннеры сервисов не получены.")
		return nil
	}
	anyVuln := false
	for _, f := range findings {
		head := f.Banner
		if f.Port > 0 {
			head = fmt.Sprintf("порт %d: %s", f.Port, f.Banner)
		}
		fmt.Println(head)
		if f.Product == "" {
			fmt.Println("    продукт/версия не распознаны")
			continue
		}
		fmt.Printf("    → %s %s\n", f.Product, f.Version)
		if len(f.Vulns) == 0 {
			fmt.Println("    совпадений в базе нет")
			continue
		}
		for _, v := range f.Vulns {
			anyVuln = true
			fmt.Printf("    ⚠ %s [%s] %s\n", v.CVE, v.Severity, v.Description)
		}
	}
	fmt.Println()
	if anyVuln {
		fmt.Println("⚠ Найдены совпадения. База индикативна — проверьте вручную.")
	} else {
		fmt.Println("Совпадений с (небольшой) встроенной базой нет — это не гарантия безопасности.")
	}
	return nil
}
