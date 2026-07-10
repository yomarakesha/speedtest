// Package config persists small dashboard preferences — currently the last
// target entered in each tab — so reopening the app pre-fills the fields. It
// mirrors internal/history: a single JSON file under the user's config dir,
// tolerant of a missing/corrupt file (a bad config never blocks startup).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the remembered last targets per tab.
type Config struct {
	PingHost  string `json:"ping_host,omitempty"`
	LANHost   string `json:"lan_host,omitempty"`
	ScanHost  string `json:"scan_host,omitempty"`
	TraceHost string `json:"trace_host,omitempty"`
	HTTPURL   string `json:"http_url,omitempty"`
	AuditHost string `json:"audit_host,omitempty"`
}

// Path returns the config file location, creating the parent directory.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "speedtest")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the config. A missing or unreadable/corrupt file yields a zero
// Config rather than an error — defaults are fine and startup must not block.
func Load() Config {
	var c Config
	path, err := Path()
	if err != nil {
		return c
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c) // ignore corrupt file, keep zero value
	return c
}

// Save writes the config as indented JSON.
func Save(c Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Remember loads the config, sets the field for kind to value, and saves —
// fire-and-forget (errors ignored). kind matches the history kinds: "ping",
// "lan", "scan", "trace", "httpdl".
func Remember(kind, value string) {
	if value == "" {
		return
	}
	c := Load()
	switch kind {
	case "ping":
		c.PingHost = value
	case "lan":
		c.LANHost = value
	case "scan":
		c.ScanHost = value
	case "trace":
		c.TraceHost = value
	case "httpdl":
		c.HTTPURL = value
	case "audit":
		c.AuditHost = value
	default:
		return
	}
	_ = Save(c)
}
