package monitor

import "testing"

func TestStateRoundTrip(t *testing.T) {
	stateBaseOverride = t.TempDir()
	t.Cleanup(func() { stateBaseOverride = "" })

	key := "portdrift-h-1-1024"
	var loaded []int
	if LoadState(key, &loaded) {
		t.Error("no baseline should exist yet")
	}

	want := []int{22, 80, 443}
	if err := SaveState(key, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	var got []int
	if !LoadState(key, &got) {
		t.Fatal("baseline should load after save")
	}
	if len(got) != 3 || got[0] != 22 || got[2] != 443 {
		t.Errorf("round-trip mismatch: %v", got)
	}
}

func TestSafeKey(t *testing.T) {
	if safeKey("portdrift-http://h:80/") == "" {
		t.Error("safeKey should never be empty for non-empty input")
	}
	if safeKey("") != "unknown" {
		t.Error("empty key should map to 'unknown'")
	}
}
