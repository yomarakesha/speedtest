package audit

import (
	"encoding/json"
	"io"
)

// SARIF (Static Analysis Results Interchange Format) 2.1.0 is the standard
// consumed by GitHub code scanning, Azure DevOps and many CI dashboards.
// ExportSARIF renders a Report as a minimal but valid SARIF log so audit
// findings can be uploaded alongside code-scanning results.

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifToolURI = "https://github.com/yomarakesha/speedtest"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifText          `json:"shortDescription"`
	Properties       sarifRuleProps     `json:"properties"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	Logical []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// sarifLevel maps our severity onto the SARIF result levels. SARIF has no
// "critical", so Critical and High both map to "error".
func sarifLevel(s Severity) string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	case Low:
		return "note"
	default:
		return "none"
	}
}

// ExportSARIF writes the report as a SARIF 2.1.0 log. Each distinct Finding.Check
// becomes a rule; every finding becomes a result whose logical location is the
// audited target, so consumers can group by host.
func ExportSARIF(w io.Writer, r Report) error {
	rulesByID := map[string]sarifRule{}
	var order []string
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		if _, seen := rulesByID[f.Check]; !seen {
			tags := f.Tags
			if len(tags) == 0 {
				tags = []string{"security"}
			}
			rulesByID[f.Check] = sarifRule{
				ID:               f.Check,
				ShortDescription: sarifText{Text: f.Title},
				DefaultConfig:    sarifDefaultConfig{Level: sarifLevel(f.Severity)},
				Properties:       sarifRuleProps{Tags: tags},
			}
			order = append(order, f.Check)
		}
		msg := f.Title
		if f.Detail != "" {
			msg += " — " + f.Detail
		}
		results = append(results, sarifResult{
			RuleID:  f.Check,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				Logical: []sarifLogicalLocation{{Name: r.Target, Kind: "resource"}},
			}},
		})
	}

	rules := make([]sarifRule, 0, len(order))
	for _, id := range order {
		rules = append(rules, rulesByID[id])
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "speedtest-audit",
				InformationURI: sarifToolURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
