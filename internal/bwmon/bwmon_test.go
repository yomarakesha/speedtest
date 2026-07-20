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

func TestParseNetstatIB(t *testing.T) {
	// Real `netstat -ibn` shape: header, lo0 (skipped), en0 link row (has MAC),
	// en0 per-address rows (skipped as duplicates), a row with a trailing Coll.
	const out = `Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0   16384 <Link#1>                       100     0      12345      100     0      12345     0
en0   1500  <Link#4>    a4:83:e7:aa:bb:cc  5000     0    9000000     4000     0    3000000     0
en0   1500  192.168.1     192.168.1.5      3000     -     600000     2500     -     400000     -
en1   1500  <Link#5>    a4:83:e7:dd:ee:ff  10       0        512       8      0        256     0`
	s := parseNetstatIB(out)
	byName := map[string]NICSample{}
	for _, x := range s {
		byName[x.Name] = x
	}
	if _, ok := byName["lo0"]; ok {
		t.Error("lo0 should be skipped")
	}
	if got := byName["en0"]; got.Rx != 9000000 || got.Tx != 3000000 {
		t.Errorf("en0 = %+v, want Rx=9000000 Tx=3000000", got)
	}
	if got := byName["en1"]; got.Rx != 512 || got.Tx != 256 {
		t.Errorf("en1 = %+v, want Rx=512 Tx=256", got)
	}
	// en0 appears twice (link + address rows) but must be counted once.
	count := 0
	for _, x := range s {
		if x.Name == "en0" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("en0 counted %d times, want 1 (dedupe link row)", count)
	}
}

func TestTotals(t *testing.T) {
	rx, tx := Totals([]NICRate{{RxMbps: 1.5, TxMbps: 0.5}, {RxMbps: 2, TxMbps: 1}})
	if rx != 3.5 || tx != 1.5 {
		t.Errorf("Totals = %.2f/%.2f, want 3.5/1.5", rx, tx)
	}
}
