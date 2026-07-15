package audit

import (
	"strings"
	"testing"
)

// The embedded default rules must always parse and compile.
func TestDefaultRuleEngineLoads(t *testing.T) {
	e := DefaultRuleEngine()
	if len(e.rules) == 0 {
		t.Fatal("no default rules loaded")
	}
}

func TestContainsMatch(t *testing.T) {
	e := DefaultRuleEngine()
	fs := e.Eval(MatchInput{Banner: "220 vsFTPd 2.3.4 ready"})
	if len(fs) == 0 {
		t.Fatal("vsFTPd 2.3.4 backdoor rule did not fire")
	}
	if fs[0].Severity != Critical {
		t.Errorf("severity = %v, want Critical", fs[0].Severity)
	}
}

func TestVersionRangeFiresInsideWindow(t *testing.T) {
	e := DefaultRuleEngine()
	// 2.2.15 is inside [2.2.0, 2.2.33) -> vulnerable.
	fs := e.Eval(MatchInput{Banner: "Apache/2.2.15 (CentOS)"})
	found := false
	for _, f := range fs {
		if f.Check == "cve.known_vulnerable" {
			found = true
		}
	}
	if !found {
		t.Fatal("Apache 2.2.15 should match the version-range rule")
	}
}

func TestVersionRangeSkipsPatched(t *testing.T) {
	e := DefaultRuleEngine()
	// 2.2.34 is >= version_lt 2.2.33 -> patched, must NOT fire the auth-bypass.
	fs := e.Eval(MatchInput{Banner: "Apache/2.2.34 (Unix)"})
	for _, f := range fs {
		if f.Check == "cve.known_vulnerable" {
			t.Fatalf("patched Apache/2.2.34 falsely flagged: %s", f.Title)
		}
	}
}

func TestVersionRangeSkipsNewerBranch(t *testing.T) {
	e := DefaultRuleEngine()
	// 2.4.10 is outside the 2.2.x window entirely; the Detail names the rule id.
	fs := e.Eval(MatchInput{Banner: "Apache/2.4.10"})
	for _, f := range fs {
		if strings.Contains(f.Detail, "apache-2.2-authbypass") {
			t.Fatal("2.4.10 wrongly matched 2.2 rule")
		}
	}
}

func TestHeaderSource(t *testing.T) {
	e := DefaultRuleEngine()
	fs := e.Eval(MatchInput{Headers: map[string]string{"X-Powered-By": "PHP/8.1.2"}})
	if len(fs) == 0 {
		t.Fatal("X-Powered-By tech-disclosure rule did not fire")
	}
	if fs[0].Severity != Info {
		t.Errorf("severity = %v, want Info", fs[0].Severity)
	}
}

func TestBodySource(t *testing.T) {
	e := DefaultRuleEngine()
	fs := e.Eval(MatchInput{Body: `{"cluster_name":"docker-cluster"}`})
	found := false
	for _, f := range fs {
		if f.Check == "creds.elastic_noauth" {
			found = true
		}
	}
	if !found {
		t.Fatal("cluster_name body rule did not fire")
	}
}

func TestPortFilter(t *testing.T) {
	rules, err := parseRules([]byte(`rules:
  - id: only-8080
    check: test.port
    severity: low
    title: "only on 8080"
    source: banner
    port: 8080
    contains: "hit"`))
	if err != nil {
		t.Fatal(err)
	}
	e := &RuleEngine{rules: rules}
	if got := e.Eval(MatchInput{Port: 80, Banner: "hit"}); len(got) != 0 {
		t.Errorf("rule fired on wrong port: %v", got)
	}
	if got := e.Eval(MatchInput{Port: 8080, Banner: "hit"}); len(got) != 1 {
		t.Errorf("rule did not fire on matching port")
	}
}

func TestRejectMalformedRule(t *testing.T) {
	// two match modes at once -> invalid
	_, err := parseRules([]byte(`rules:
  - id: bad
    check: x
    severity: low
    title: t
    contains: a
    regex: b`))
	if err == nil {
		t.Fatal("expected error for rule with two match modes")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.2.15", "2.2.33", -1},
		{"2.2.34", "2.2.33", 1},
		{"1.4", "1.4.0", 0},
		{"1.4.1", "1.4.0", 1},
		{"10.0", "9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	v, ok := extractVersion("Apache/2.4.49 (Unix)", "Apache")
	if !ok || v != "2.4.49" {
		t.Errorf("got %q,%v want 2.4.49,true", v, ok)
	}
	if _, ok := extractVersion("nginx", "Apache"); ok {
		t.Error("should not find Apache in nginx banner")
	}
}
