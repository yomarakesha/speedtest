package util

import (
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		err  bool
	}{
		{"2048", 2048, false},
		{"1K", 1024, false},
		{"1KB", 1024, false},
		{"1kb", 1024, false},
		{"1M", 1 << 20, false},
		{"100MB", 100 << 20, false},
		{"1.5G", 1<<30 + 1<<29, false},
		{"  512k ", 512 * 1024, false},
		{"", 0, true},
		{"abc", 0, true},
		{"12x", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseSize(%q): expected error, got %d", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSize(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{1024, "1.00 KiB"},
		{1536, "1.50 KiB"},
		{1 << 20, "1.00 MiB"},
		{1 << 30, "1.00 GiB"},
	}
	for _, c := range cases {
		if got := Bytes(c.in); got != c.want {
			t.Errorf("Bytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMbps(t *testing.T) {
	// 1,000,000 bytes in 1s = 8 Mbps.
	if got := Mbps(1_000_000, time.Second); got != 8 {
		t.Errorf("Mbps(1e6, 1s) = %v, want 8", got)
	}
	if got := Mbps(1000, 0); got != 0 {
		t.Errorf("Mbps with zero duration = %v, want 0", got)
	}
}

func TestSanitizeLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"esc\x1b[31mred", "esc[31mred"},
		{"tab\tnl\nend", "tabnlend"},
		{"del\x7fhere", "delhere"},
		{"c1\u009bCSI", "c1CSI"},
		{"кириллица ok", "кириллица ok"},
	}
	for _, c := range cases {
		if got := SanitizeLine(c.in); got != c.want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
