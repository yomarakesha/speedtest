// Package util holds small formatting and parsing helpers shared across commands.
package util

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseFlags parses args allowing flags and positional arguments to be
// interspersed (Go's flag package stops at the first positional otherwise).
// It returns the collected positional arguments.
func ParseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	return positional, nil
}

// ParseSize parses a human byte size like "100MB", "1.5G", "512kb", "2048".
// A bare number is treated as bytes. Units are powers of 1024.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("пустой размер")
	}
	up := strings.ToUpper(s)
	up = strings.TrimSuffix(up, "B") // allow "MB" and "M" alike

	mult := int64(1)
	switch {
	case strings.HasSuffix(up, "K"):
		mult, up = 1<<10, strings.TrimSuffix(up, "K")
	case strings.HasSuffix(up, "M"):
		mult, up = 1<<20, strings.TrimSuffix(up, "M")
	case strings.HasSuffix(up, "G"):
		mult, up = 1<<30, strings.TrimSuffix(up, "G")
	}

	f, err := strconv.ParseFloat(strings.TrimSpace(up), 64)
	if err != nil {
		return 0, fmt.Errorf("некорректный размер %q", s)
	}
	return int64(f * float64(mult)), nil
}

// Bytes formats a byte count as a human string (base 1024).
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Mbps converts a transfer of n bytes over d into megabits per second.
func Mbps(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) * 8 / d.Seconds() / 1e6
}
