package monitor

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the parsed monitor.yaml: a list of checks plus which sinks receive
// their alerts.
type Config struct {
	Checks []CheckSpec `yaml:"checks"`
	Sinks  SinkConfig  `yaml:"sinks"`
}

// CheckSpec is one check. Only the fields relevant to Type are read; unused ones
// are ignored. Durations accept Go syntax ("10s", "5m", "1h").
type CheckSpec struct {
	Type     string   `yaml:"type"`     // ping | portdrift | auditgrade | bandwidth
	Target   string   `yaml:"target"`   // host (ping/portdrift/auditgrade)
	Iface    string   `yaml:"iface"`    // interface name substring (bandwidth); empty = all
	Interval Duration `yaml:"interval"` // poll cadence for `monitor run`

	// ping
	Count      int      `yaml:"count"`       // attempts per pass (default 5)
	MaxLatency Duration `yaml:"max_latency"` // breach if avg RTT exceeds this
	MaxLoss    float64  `yaml:"max_loss"`    // breach if loss % exceeds this

	// portdrift
	Ports string `yaml:"ports"` // spec, e.g. "1-1024" (default) or "22,80,443"

	// auditgrade
	MinGrade string `yaml:"min_grade"` // breach if grade drops below this (A..F)
	Active   bool   `yaml:"active"`    // enable intrusive audit checks (needs authorization)

	// bandwidth
	MaxMbps float64 `yaml:"max_mbps"` // breach if rx or tx exceeds this
}

// SinkConfig selects which alert destinations are enabled.
type SinkConfig struct {
	Stdout  bool   `yaml:"stdout"`
	Webhook string `yaml:"webhook"` // POST target URL; empty disables
	Desktop bool   `yaml:"desktop"`
	History bool   `yaml:"history"`
}

// Duration is a time.Duration that unmarshals from a YAML string like "10s".
type Duration time.Duration

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML parses a duration from a string ("10s") or a bare number of
// seconds.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	// A bare number (no unit) is seconds; a string like "10s" is a Go duration.
	var secs float64
	if err := value.Decode(&secs); err == nil {
		*d = Duration(time.Duration(secs * float64(time.Second)))
		return nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("длительность должна быть строкой (\"10s\") или числом секунд")
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("некорректная длительность %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// LoadConfig reads and parses a monitor config file.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(b)
}

// ParseConfig parses config bytes and validates them.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// validate rejects configs that can never run: no checks, unknown types, or a
// check missing the target/iface its type needs.
func (c Config) validate() error {
	if len(c.Checks) == 0 {
		return fmt.Errorf("в конфиге нет ни одной проверки (checks)")
	}
	for i, ch := range c.Checks {
		switch ch.Type {
		case "ping", "portdrift", "auditgrade":
			if ch.Target == "" {
				return fmt.Errorf("checks[%d] (%s): не задан target", i, ch.Type)
			}
		case "bandwidth":
			// iface optional (empty = all interfaces)
		case "":
			return fmt.Errorf("checks[%d]: не задан type", i)
		default:
			return fmt.Errorf("checks[%d]: неизвестный type %q", i, ch.Type)
		}
	}
	return nil
}

// SampleConfig is a ready-to-edit example written when no config is found.
const SampleConfig = `# monitor.yaml — непрерывный мониторинг сети
checks:
  - type: ping
    target: 1.1.1.1
    interval: 10s
    count: 5
    max_latency: 80ms
    max_loss: 5          # проценты

  - type: portdrift       # сообщать об открытии/закрытии портов
    target: 192.168.1.1
    interval: 5m
    ports: 1-1024

  - type: auditgrade      # сообщать о падении оценки безопасности
    target: example.com
    interval: 1h
    min_grade: B

  - type: bandwidth       # трафик ЭТОЙ машины
    iface: ""             # пусто = все интерфейсы
    interval: 2s
    max_mbps: 900

sinks:
  stdout: true
  webhook: ""             # напр. https://hooks.slack.com/services/...
  desktop: false
  history: true
`
