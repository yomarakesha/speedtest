package audit

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed rules_default.yaml
var defaultRulesYAML []byte

// Rule is a declarative check matched against evidence gathered from a host. It
// is the data-driven replacement for hard-coded Go check tables, so new checks
// (CVE leads, header/body signatures) can be added as YAML without recompiling.
type Rule struct {
	ID       string `yaml:"id"`
	Check    string `yaml:"check"`    // Finding.Check id
	Severity string `yaml:"severity"` // info|low|medium|high|critical
	Title    string `yaml:"title"`
	CVE      string `yaml:"cve,omitempty"`

	Source string `yaml:"source"` // banner|header|body|status (default banner)
	Port   int    `yaml:"port,omitempty"`
	Header string `yaml:"header,omitempty"` // required when source == header

	// Match modes — exactly one group must be set.
	Contains string `yaml:"contains,omitempty"`
	Regex    string `yaml:"regex,omitempty"`

	Product   string `yaml:"product,omitempty"`
	VersionGE string `yaml:"version_ge,omitempty"`
	VersionLT string `yaml:"version_lt,omitempty"`

	re *regexp.Regexp // compiled Regex, set by compile
}

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

// MatchInput is the evidence a single service/response offers to the engine.
type MatchInput struct {
	Port    int
	Banner  string
	Headers map[string]string // canonical header name -> value
	Body    string
	Status  int
}

// severityFromString parses a rule's severity label; unknown values map to Info
// so a typo degrades to a harmless note rather than an over-severe finding.
func severityFromString(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium":
		return Medium
	case "low":
		return Low
	default:
		return Info
	}
}

// compile validates a rule and pre-compiles its regex. It returns an error so a
// malformed rule is rejected at load time rather than silently never matching.
func (r *Rule) compile() error {
	if r.ID == "" || r.Check == "" || r.Title == "" {
		return fmt.Errorf("rule missing id/check/title")
	}
	modes := 0
	if r.Contains != "" {
		modes++
	}
	if r.Regex != "" {
		modes++
	}
	if r.VersionLT != "" || r.VersionGE != "" {
		if r.Product == "" {
			return fmt.Errorf("rule %s: version match needs product", r.ID)
		}
		modes++
	}
	if modes != 1 {
		return fmt.Errorf("rule %s: set exactly one of contains/regex/version", r.ID)
	}
	if r.Source == "header" && r.Header == "" {
		return fmt.Errorf("rule %s: source=header needs header name", r.ID)
	}
	if r.Regex != "" {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return fmt.Errorf("rule %s: bad regex: %w", r.ID, err)
		}
		r.re = re
	}
	return nil
}

// haystack returns the text a rule inspects for the given input.
func (r *Rule) haystack(in MatchInput) string {
	switch r.Source {
	case "header":
		return in.Headers[r.Header]
	case "body":
		return in.Body
	case "status":
		return strconv.Itoa(in.Status)
	default: // banner
		return in.Banner
	}
}

// eval returns a Finding when the rule matches the input, or nil.
func (r *Rule) eval(in MatchInput) *Finding {
	if r.Port != 0 && in.Port != 0 && r.Port != in.Port {
		return nil
	}
	hay := r.haystack(in)
	if hay == "" {
		return nil
	}

	var evidence string
	switch {
	case r.Contains != "":
		if !strings.Contains(strings.ToLower(hay), strings.ToLower(r.Contains)) {
			return nil
		}
		evidence = hay
	case r.re != nil:
		m := r.re.FindString(hay)
		if m == "" {
			return nil
		}
		evidence = m
	default: // version compare
		ver, ok := extractVersion(hay, r.Product)
		if !ok {
			return nil
		}
		if r.VersionGE != "" && compareVersions(ver, r.VersionGE) < 0 {
			return nil
		}
		if r.VersionLT != "" && compareVersions(ver, r.VersionLT) >= 0 {
			return nil
		}
		evidence = r.Product + "/" + ver
	}

	title := r.Title
	if r.CVE != "" {
		title = r.CVE + ": " + r.Title
	}
	return &Finding{
		Check:    r.Check,
		Severity: severityFromString(r.Severity),
		Title:    title,
		Detail:   "по правилу " + r.ID,
		Evidence: strings.TrimSpace(evidence),
	}
}

// RuleEngine holds a compiled set of rules.
type RuleEngine struct {
	rules []Rule
}

// Eval runs every rule against one input and returns all matching findings.
func (e *RuleEngine) Eval(in MatchInput) []Finding {
	var out []Finding
	for i := range e.rules {
		if f := e.rules[i].eval(in); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// parseRules unmarshals a YAML rule file and compiles each rule.
func parseRules(data []byte) ([]Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}
	for i := range rf.Rules {
		if err := rf.Rules[i].compile(); err != nil {
			return nil, err
		}
	}
	return rf.Rules, nil
}

// LoadRuleEngine builds an engine from the embedded default rules plus any
// *.yaml/*.yml files in extraDirs (later files add to, never replace, the
// defaults). A malformed external file is reported but does not abort the load
// of the rest.
func LoadRuleEngine(extraDirs ...string) (*RuleEngine, error) {
	rules, err := parseRules(defaultRulesYAML)
	if err != nil {
		return nil, fmt.Errorf("встроенные правила: %w", err)
	}
	for _, dir := range extraDirs {
		if dir == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "audit: не читается %s: %v\n", path, err)
				continue
			}
			extra, err := parseRules(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "audit: пропущен %s: %v\n", path, err)
				continue
			}
			rules = append(rules, extra...)
		}
	}
	return &RuleEngine{rules: rules}, nil
}

var (
	defaultEngine     *RuleEngine
	defaultEngineOnce sync.Once
)

// DefaultRuleEngine returns the process-wide engine built from the embedded
// rules, loaded once. It panics only on a malformed embedded file, which is a
// build-time authoring error caught by tests.
func DefaultRuleEngine() *RuleEngine {
	defaultEngineOnce.Do(func() {
		e, err := LoadRuleEngine()
		if err != nil {
			panic(err)
		}
		defaultEngine = e
	})
	return defaultEngine
}

var versionTokenRe = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)*`)

// extractVersion pulls the dotted version that follows product (e.g. the "2.4.49"
// in "Apache/2.4.49") out of s, case-insensitively. ok is false when product is
// absent or no version follows it.
func extractVersion(s, product string) (string, bool) {
	low := strings.ToLower(s)
	idx := strings.Index(low, strings.ToLower(product))
	if idx < 0 {
		return "", false
	}
	rest := s[idx+len(product):]
	// Skip a single separator (/ space -) between product and version.
	rest = strings.TrimLeft(rest, "/ -_v")
	m := versionTokenRe.FindString(rest)
	if m == "" {
		return "", false
	}
	return m, true
}

// compareVersions compares two dotted numeric versions, returning -1, 0, or 1.
// Missing trailing components count as zero (1.4 == 1.4.0).
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := max(len(as), len(bs))
	for i := range n {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
