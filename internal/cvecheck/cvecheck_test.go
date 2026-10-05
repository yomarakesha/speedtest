package cvecheck

import "testing"

func TestParseBanner(t *testing.T) {
	cases := []struct {
		banner      string
		wantProduct string
		wantVersion string
	}{
		{"Apache/2.4.49 (Unix)", "apache", "2.4.49"},
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu", "openssh", "8.2p1"},
		{"220 (vsFTPd 2.3.4)", "vsftpd", "2.3.4"},
		{"ProFTPD 1.3.5 Server", "proftpd", "1.3.5"},
		{"some random text", "", ""},
	}
	for _, c := range cases {
		p, v := ParseBanner(c.banner)
		if p != c.wantProduct || v != c.wantVersion {
			t.Errorf("ParseBanner(%q) = (%q,%q), want (%q,%q)", c.banner, p, v, c.wantProduct, c.wantVersion)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.50", -1},
		{"2.4.50", "2.4.49", 1},
		{"2.4.49", "2.4.49", 0},
		{"1.3.5", "1.3.5a", -1},
		{"1.3.5a", "1.3.5", 1},
		{"8.2p1", "8.2", 1},
		{"7.7", "7.7", 0},
		{"2.4", "2.4.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchVulnerable(t *testing.T) {
	v := Match("apache", "2.4.49")
	if len(v) == 0 {
		t.Fatal("Apache 2.4.49 should match CVE-2021-41773")
	}
	found := false
	for _, x := range v {
		if x.CVE == "CVE-2021-41773" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2021-41773, got %v", v)
	}
}

func TestMatchFixed(t *testing.T) {
	if v := Match("apache", "2.4.51"); len(v) != 0 {
		t.Errorf("Apache 2.4.51 is patched, got %v", v)
	}
	if v := Match("vsftpd", "2.3.4"); len(v) == 0 {
		t.Error("vsftpd 2.3.4 should match the backdoor CVE")
	}
	if v := Match("vsftpd", "3.0.3"); len(v) != 0 {
		t.Errorf("vsftpd 3.0.3 should be clean, got %v", v)
	}
}

func TestMatchUnknownProduct(t *testing.T) {
	if v := Match("totally-unknown", "1.0"); len(v) != 0 {
		t.Errorf("unknown product should not match, got %v", v)
	}
}
