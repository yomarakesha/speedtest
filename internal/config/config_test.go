package config

import "testing"

func TestRememberRoundTrip(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())         // Windows UserConfigDir
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // Linux
	t.Setenv("HOME", t.TempDir())            // macOS fallback

	Remember("ping", "8.8.8.8")
	Remember("httpdl", "http://cam/snap.jpg")
	Remember("bogus", "ignored") // unknown kind is a no-op

	c := Load()
	if c.PingHost != "8.8.8.8" {
		t.Errorf("PingHost = %q, want 8.8.8.8", c.PingHost)
	}
	if c.HTTPURL != "http://cam/snap.jpg" {
		t.Errorf("HTTPURL = %q, want the camera URL", c.HTTPURL)
	}
	if c.LANHost != "" {
		t.Errorf("LANHost should be empty, got %q", c.LANHost)
	}
}

func TestLoadMissingIsZero(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	if c := Load(); c != (Config{}) {
		t.Errorf("missing config should load as zero, got %+v", c)
	}
}
