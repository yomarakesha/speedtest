package monitor

import (
	"testing"
	"time"
)

func TestParseConfig(t *testing.T) {
	yaml := `
checks:
  - type: ping
    target: 1.1.1.1
    interval: 10s
    max_latency: 80ms
    max_loss: 5
  - type: bandwidth
    interval: 2s
    max_mbps: 900
sinks:
  stdout: true
  webhook: https://example.com/hook
  history: true
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Checks) != 2 {
		t.Fatalf("want 2 checks, got %d", len(cfg.Checks))
	}
	if cfg.Checks[0].Interval.D() != 10*time.Second {
		t.Errorf("interval: want 10s, got %v", cfg.Checks[0].Interval.D())
	}
	if cfg.Checks[0].MaxLatency.D() != 80*time.Millisecond {
		t.Errorf("max_latency: want 80ms, got %v", cfg.Checks[0].MaxLatency.D())
	}
	if cfg.Checks[0].MaxLoss != 5 {
		t.Errorf("max_loss: want 5, got %v", cfg.Checks[0].MaxLoss)
	}
	if !cfg.Sinks.Stdout || cfg.Sinks.Webhook == "" || !cfg.Sinks.History {
		t.Errorf("sinks not parsed: %+v", cfg.Sinks)
	}
}

func TestParseConfigNumericSeconds(t *testing.T) {
	cfg, err := ParseConfig([]byte("checks:\n  - {type: ping, target: x, interval: 15}\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Checks[0].Interval.D() != 15*time.Second {
		t.Errorf("numeric interval: want 15s, got %v", cfg.Checks[0].Interval.D())
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]string{
		"no checks":      "sinks: {stdout: true}\n",
		"unknown type":   "checks:\n  - {type: bogus, target: x}\n",
		"missing type":   "checks:\n  - {target: x}\n",
		"ping no target": "checks:\n  - {type: ping, interval: 10s}\n",
	}
	for name, yaml := range cases {
		if _, err := ParseConfig([]byte(yaml)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestBandwidthNoTargetOK(t *testing.T) {
	// bandwidth with empty iface is valid (means all interfaces).
	if _, err := ParseConfig([]byte("checks:\n  - {type: bandwidth, max_mbps: 100}\n")); err != nil {
		t.Errorf("bandwidth without iface should be valid: %v", err)
	}
}

func TestBadDuration(t *testing.T) {
	if _, err := ParseConfig([]byte("checks:\n  - {type: ping, target: x, interval: \"nope\"}\n")); err == nil {
		t.Error("expected error for bad duration")
	}
}
