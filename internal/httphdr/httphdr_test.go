package httphdr

import (
	"net/http"
	"testing"
)

func TestGrade(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"}, {79, "C"},
		{70, "C"}, {69, "D"}, {60, "D"}, {59, "F"}, {0, "F"},
	}
	for _, c := range cases {
		if got := Grade(c.score); got != c.want {
			t.Errorf("Grade(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestAnalyzeAllPresent(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=63072000")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=()")

	_, score := analyze(h, nil)
	if score != 100 {
		t.Errorf("all present: score = %d, want 100", score)
	}
	if Grade(score) != "A" {
		t.Errorf("all present: grade = %q, want A", Grade(score))
	}
}

func TestAnalyzeNonePresent(t *testing.T) {
	_, score := analyze(http.Header{}, nil)
	if score != 0 {
		t.Errorf("none present: score = %d, want 0", score)
	}
}

func TestAnalyzeNosniffWrongValue(t *testing.T) {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "sniff") // wrong value, must not count
	// Everything else missing; only X-Content-Type-Options present-but-weak.
	_, score := analyze(h, nil)
	// 100 - all weights (25+25+15+15+10+10) = 0, X-C-T-O weak also deducted.
	if score != 0 {
		t.Errorf("weak nosniff: score = %d, want 0", score)
	}
}

func TestWeakCookies(t *testing.T) {
	cookies := []string{
		"sid=abc; Secure; HttpOnly; SameSite=Lax", // strong
		"tracker=1",      // weak: no flags
		"csrf=x; Secure", // weak: missing HttpOnly/SameSite
	}
	weak := weakCookies(cookies)
	if len(weak) != 2 {
		t.Fatalf("weakCookies = %v, want 2 entries", weak)
	}
	if weak[0] != "csrf" || weak[1] != "tracker" {
		t.Errorf("weakCookies = %v, want [csrf tracker] (sorted)", weak)
	}
}

func TestNormalizeURL(t *testing.T) {
	if got := normalizeURL("example.com"); got != "https://example.com" {
		t.Errorf("normalizeURL bare = %q", got)
	}
	if got := normalizeURL("http://example.com"); got != "http://example.com" {
		t.Errorf("normalizeURL with scheme = %q", got)
	}
}
