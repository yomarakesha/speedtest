package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// stateBaseOverride redirects the state dir in tests. Empty = user config dir.
var stateBaseOverride string

// stateDir is the per-user directory holding drift baselines (e.g. the last set
// of open ports seen for a portdrift check).
func stateDir() (string, error) {
	base := stateBaseOverride
	if base == "" {
		b, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(b, "speedtest")
	}
	dir := filepath.Join(base, "monitor-state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// safeKey maps an arbitrary key to a flat, filesystem-safe filename.
func safeKey(key string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, key)
	if safe == "" {
		return "unknown"
	}
	return safe
}

// LoadState reads the JSON baseline for key into v. ok is false when no baseline
// exists yet (first run of this check) or it can't be read.
func LoadState(key string, v any) (ok bool) {
	dir, err := stateDir()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join(dir, safeKey(key)+".json"))
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// SaveState writes v as the JSON baseline for key, overwriting any previous one.
func SaveState(key string, v any) error {
	dir, err := stateDir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, safeKey(key)+".json"), b, 0o644)
}
