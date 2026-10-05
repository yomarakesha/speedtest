package ntp

import (
	"testing"
	"time"
)

func TestNTPTimeRoundTrip(t *testing.T) {
	orig := time.Date(2026, 10, 5, 12, 30, 45, 500_000_000, time.UTC)
	sec, frac := fromNTPTime(orig)
	got := toNTPTime(sec, frac)
	if diff := got.Sub(orig); diff < -time.Millisecond || diff > time.Millisecond {
		t.Errorf("round-trip drift %v (got %v, want %v)", diff, got, orig)
	}
}

func TestToNTPTimeEpoch(t *testing.T) {
	// NTP seconds == ntpEpochOffset is the Unix epoch.
	got := toNTPTime(ntpEpochOffset, 0)
	if !got.Equal(time.Unix(0, 0).UTC()) {
		t.Errorf("toNTPTime(epoch) = %v, want Unix epoch", got)
	}
}

func TestOffsetRTT(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Server clock is exactly 100ms ahead; symmetric 20ms each way.
	t1 := base
	t2 := base.Add(20*time.Millisecond + 100*time.Millisecond) // recv at server
	t3 := t2.Add(5 * time.Millisecond)                         // server processing
	t4 := t1.Add(20*time.Millisecond + 5*time.Millisecond + 20*time.Millisecond)

	offset, rtt := offsetRTT(t1, t2, t3, t4)
	if offset < 99 || offset > 101 {
		t.Errorf("offset = %.2f ms, want ~100", offset)
	}
	if rtt < 39 || rtt > 41 {
		t.Errorf("rtt = %.2f ms, want ~40", rtt)
	}
}
