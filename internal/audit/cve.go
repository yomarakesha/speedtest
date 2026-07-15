package audit

import (
	"time"

	"speedtest/internal/portscan"
)

// cveForBanner returns findings for any rule that matches banner. It is a thin
// wrapper over the declarative rule engine, kept for callers that only have a
// banner in hand.
func cveForBanner(banner string) []Finding {
	if banner == "" {
		return nil
	}
	return DefaultRuleEngine().Eval(MatchInput{Banner: banner})
}

// AuditBannerCVEs scans a small set of common service ports, grabs their
// banners, and matches them against the rule engine. Rules are data-driven
// (see rules_default.yaml) so new signatures need no code change.
func AuditBannerCVEs(host string, timeout time.Duration) []Finding {
	ports := []int{21, 22, 25, 80, 8080}
	infos := make([]portscan.PortInfo, len(ports))
	for i, p := range ports {
		infos[i] = portscan.PortInfo{Port: p}
	}
	portscan.AddBanners(host, infos, timeout)

	engine := DefaultRuleEngine()
	var out []Finding
	for _, pi := range infos {
		out = append(out, engine.Eval(MatchInput{Port: pi.Port, Banner: pi.Banner})...)
	}
	return out
}
