package audit

import (
	"strings"
	"time"

	"speedtest/internal/portscan"
)

// cveRule matches a banner substring to a known vulnerability. This is a small
// illustrative table, not a comprehensive vulnerability database — treat hits
// as leads to verify, not confirmed exploitable findings.
type cveRule struct {
	match    string // case-insensitive substring of the service banner
	cve      string
	severity Severity
	title    string
}

var cveRules = []cveRule{
	{"OpenSSH_7.2", "CVE-2016-6210", Medium, "OpenSSH 7.2: перечисление пользователей по времени ответа"},
	{"OpenSSH_6.6", "CVE-2015-5600", Medium, "OpenSSH 6.6: обход ограничения попыток аутентификации (keyboard-interactive)"},
	{"vsFTPd 2.3.4", "CVE-2011-2523", Critical, "vsftpd 2.3.4: бэкдор с удалённым выполнением команд"},
	{"ProFTPD 1.3.3", "CVE-2010-4221", Critical, "ProFTPD 1.3.3: удалённое переполнение буфера"},
	{"Apache/2.4.49", "CVE-2021-41773", Critical, "Apache 2.4.49: обход пути и RCE"},
	{"Apache/2.2.", "CVE-2017-3167", High, "Apache 2.2.x: обход аутентификации (устаревшая ветка)"},
	{"nginx/1.3.", "CVE-2013-2028", High, "nginx 1.3.x/1.4.0: переполнение стека при chunked-запросах"},
	{"Exim 4.87", "CVE-2019-10149", Critical, "Exim 4.87–4.91: удалённое выполнение команд (return-path)"},
	{"Microsoft-IIS/6.0", "CVE-2017-7269", Critical, "IIS 6.0: переполнение буфера в WebDAV (ScStoragePathFromUrl)"},
}

// cveForBanner returns findings for any rule whose match appears in banner.
func cveForBanner(banner string) []Finding {
	if banner == "" {
		return nil
	}
	low := strings.ToLower(banner)
	var out []Finding
	for _, r := range cveRules {
		if strings.Contains(low, strings.ToLower(r.match)) {
			out = append(out, Finding{
				Check:    "cve.known_vulnerable",
				Severity: r.severity,
				Title:    r.cve + ": " + r.title,
				Detail:   "по баннеру: " + banner,
				Evidence: banner,
			})
		}
	}
	return out
}

// AuditBannerCVEs scans a small set of common service ports, grabs their
// banners, and matches them against the CVE rule table.
func AuditBannerCVEs(host string, timeout time.Duration) []Finding {
	ports := []int{21, 22, 25, 80, 8080}
	infos := make([]portscan.PortInfo, len(ports))
	for i, p := range ports {
		infos[i] = portscan.PortInfo{Port: p}
	}
	portscan.AddBanners(host, infos, timeout)

	var out []Finding
	for _, pi := range infos {
		out = append(out, cveForBanner(pi.Banner)...)
	}
	return out
}
