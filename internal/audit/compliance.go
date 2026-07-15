package audit

import "strings"

// complianceTags maps a Finding.Check id to the compliance controls it relates
// to, so reports and SARIF output can be filtered by framework. Mapping is by
// the check's category prefix (the part before the first dot); an unknown check
// still gets the generic "security" tag.
//
// References: OWASP Top 10 (2021) categories and CIS Controls v8.
func complianceTags(check string) []string {
	category, _, _ := strings.Cut(check, ".")
	tags := []string{"security"}
	switch category {
	case "tls":
		tags = append(tags, "OWASP:A02:2021-Cryptographic-Failures", "CIS:3.10")
	case "http":
		tags = append(tags, "OWASP:A05:2021-Security-Misconfiguration", "CIS:4.1")
	case "web":
		tags = append(tags, "OWASP:A05:2021-Security-Misconfiguration",
			"OWASP:A01:2021-Broken-Access-Control")
	case "creds", "snmp":
		tags = append(tags, "OWASP:A07:2021-Identification-and-Authentication-Failures",
			"CIS:4.7")
	case "cve":
		tags = append(tags, "OWASP:A06:2021-Vulnerable-and-Outdated-Components", "CIS:7.1")
	case "port", "smb":
		tags = append(tags, "OWASP:A05:2021-Security-Misconfiguration", "CIS:4.8")
	case "dns":
		tags = append(tags, "OWASP:A05:2021-Security-Misconfiguration", "CIS:12.2")
	}
	return tags
}
