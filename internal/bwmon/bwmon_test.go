package bwmon

import (
	"testing"
	"time"
)

func TestComputeRates(t *testing.T) {
	prev := []NICSample{
		{Name: "eth0", Rx: 1_000_000, Tx: 500_000},
		{Name: "wlan0", Rx: 0, Tx: 0},
	}
	cur := []NICSample{
		{Name: "eth0", Rx: 2_250_000, Tx: 500_000}, // +1.25 MB rx over 1s = 10 Mbps
		{Name: "wlan0", Rx: 100, Tx: 50},           // brand-new traffic
		{Name: "tun0", Rx: 999, Tx: 999},           // absent from prev => rate 0
	}
	rates := computeRates(prev, cur, time.Second)

	byName := map[string]NICRate{}
	for _, r := range rates {
		byName[r.Name] = r
	}
	if got := byName["eth0"].RxMbps; got < 9.99 || got > 10.01 {
		t.Errorf("eth0 RxMbps = %.4f, want ~10", got)
	}
	if got := byName["eth0"].TxMbps; got != 0 {
		t.Errorf("eth0 TxMbps = %.4f, want 0", got)
	}
	if byName["tun0"].RxMbps != 0 {
		t.Errorf("tun0 (new iface) should have zero rate, got %.4f", byName["tun0"].RxMbps)
	}
	if byName["eth0"].Rx != 2_250_000 {
		t.Errorf("cumulative Rx not carried: %d", byName["eth0"].Rx)
	}
}

func TestComputeRatesCounterReset(t *testing.T) {
	// Counter went backwards (interface reset): rate must be 0, not a huge spike.
	prev := []NICSample{{Name: "eth0", Rx: 5_000_000, Tx: 5_000_000}}
	cur := []NICSample{{Name: "eth0", Rx: 1000, Tx: 1000}}
	rates := computeRates(prev, cur, time.Second)
	if rates[0].RxMbps != 0 || rates[0].TxMbps != 0 {
		t.Errorf("counter reset should yield 0 rate, got %+v", rates[0])
	}
}

func TestParseNetAdapterCSV(t *testing.T) {
	const csv = `"Name","ReceivedBytes","SentBytes"
"Ethernet","194955886","6512476"
"Беспроводная сеть","209080149","47260210"
"bad","notanumber","0"`
	s, err := parseNetAdapterCSV(csv)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 { // bad row dropped
		t.Fatalf("got %d samples, want 2: %+v", len(s), s)
	}
	if s[0].Name != "Ethernet" || s[0].Rx != 194955886 || s[0].Tx != 6512476 {
		t.Errorf("row0 = %+v", s[0])
	}
	if s[1].Name != "Беспроводная сеть" || s[1].Rx != 209080149 {
		t.Errorf("row1 = %+v", s[1])
	}
}

func TestParseProcNetDev(t *testing.T) {
	const dev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
  eth0: 5000000    4000    0    0    0     0          0         0  1000000    3000    0    0    0     0       0          0`
	s := parseProcNetDev(dev)
	if len(s) != 1 { // lo skipped
		t.Fatalf("got %d samples, want 1 (lo skipped): %+v", len(s), s)
	}
	if s[0].Name != "eth0" || s[0].Rx != 5000000 || s[0].Tx != 1000000 {
		t.Errorf("eth0 = %+v", s[0])
	}
}

func TestTotals(t *testing.T) {
	rx, tx := Totals([]NICRate{{RxMbps: 1.5, TxMbps: 0.5}, {RxMbps: 2, TxMbps: 1}})
	if rx != 3.5 || tx != 1.5 {
		t.Errorf("Totals = %.2f/%.2f, want 3.5/1.5", rx, tx)
	}
}
