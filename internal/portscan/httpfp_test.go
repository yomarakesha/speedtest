package portscan

import (
	"net/http"
	"slices"
	"testing"
)

func TestPageTitle(t *testing.T) {
	cases := []struct{ body, want string }{
		{`<html><head><title>Hello World</title></head>`, "Hello World"},
		{"<TITLE>\n  Spaced\t Out  \n</TITLE>", "Spaced Out"},
		{`<title lang="en">Attr</title>`, "Attr"},
		{"<html>no title here</html>", ""},
	}
	for _, c := range cases {
		if got := pageTitle([]byte(c.body)); got != c.want {
			t.Errorf("pageTitle(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestDetectTechFromHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.3")
	h.Set("X-Powered-By", "PHP/8.2.0")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	got := detectTech(h, "")
	for _, want := range []string{"nginx", "PHP", "HSTS"} {
		if !slices.Contains(got, want) {
			t.Errorf("detectTech missed %q; got %v", want, got)
		}
	}
}

func TestDetectTechFromBody(t *testing.T) {
	body := `<html data-reactroot><link href="/wp-content/style.css"><script src="/_next/static/x.js">`
	got := detectTech(http.Header{}, body)
	for _, want := range []string{"React", "WordPress", "Next.js"} {
		if !slices.Contains(got, want) {
			t.Errorf("detectTech missed %q; got %v", want, got)
		}
	}
}

func TestDetectTechDeduplicates(t *testing.T) {
	// WordPress has two signatures; a page with both must list it once.
	body := `<a href="/wp-content/x">/wp-includes/y`
	got := detectTech(http.Header{}, body)
	count := 0
	for _, g := range got {
		if g == "WordPress" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("WordPress listed %d times, want 1 (got %v)", count, got)
	}
}

func TestIsWebPort(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 8443, 3000, 9090} {
		if !isWebPort(p) {
			t.Errorf("isWebPort(%d) = false, want true", p)
		}
	}
	for _, p := range []int{22, 3306, 6379} {
		if isWebPort(p) {
			t.Errorf("isWebPort(%d) = true, want false", p)
		}
	}
}
