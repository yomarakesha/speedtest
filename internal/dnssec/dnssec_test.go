package dnssec

import (
	"encoding/binary"
	"testing"
)

func TestParseSPF(t *testing.T) {
	txts := []string{"some=verification", "v=spf1 include:_spf.google.com ~all"}
	rec, ok := parseSPF(txts)
	if !ok || rec != "v=spf1 include:_spf.google.com ~all" {
		t.Errorf("parseSPF = %q, %v", rec, ok)
	}
	if _, ok := parseSPF([]string{"no spf here"}); ok {
		t.Error("parseSPF found SPF where none exists")
	}
}

func TestParseDMARC(t *testing.T) {
	rec, pol, ok := parseDMARC([]string{"v=DMARC1; p=reject; rua=mailto:a@b.c"})
	if !ok {
		t.Fatal("parseDMARC: not found")
	}
	if pol != "reject" {
		t.Errorf("policy = %q, want reject", pol)
	}
	if rec == "" {
		t.Error("record empty")
	}
	if _, _, ok := parseDMARC([]string{"v=spf1 ~all"}); ok {
		t.Error("parseDMARC matched a non-DMARC record")
	}
}

func TestTxtData(t *testing.T) {
	ans := []dohAnswer{
		{Type: 16, Data: `"v=spf1 ~all"`},
		{Type: 1, Data: "1.2.3.4"},
		{Type: 16, Data: `"other"`},
	}
	got := txtData(ans)
	if len(got) != 2 || got[0] != "v=spf1 ~all" || got[1] != "other" {
		t.Errorf("txtData = %v", got)
	}
}

func TestBuildQuery(t *testing.T) {
	msg := buildQuery(0x1234, "example.com", 252, false)
	if binary.BigEndian.Uint16(msg[0:]) != 0x1234 {
		t.Error("id mismatch")
	}
	if binary.BigEndian.Uint16(msg[4:]) != 1 {
		t.Error("qdcount != 1")
	}
	// question: 7 'example' 3 'com' 0 + qtype(2) + qclass(2)
	want := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	q := msg[12:]
	for i, b := range want {
		if q[i] != b {
			t.Fatalf("qname byte %d = %d, want %d", i, q[i], b)
		}
	}
	qtype := binary.BigEndian.Uint16(q[len(want):])
	if qtype != 252 {
		t.Errorf("qtype = %d, want 252", qtype)
	}
}

func TestHeaderCounts(t *testing.T) {
	msg := make([]byte, 12)
	msg[3] = 0x05 // rcode = REFUSED
	binary.BigEndian.PutUint16(msg[6:], 7)
	rcode, ancount, ok := headerCounts(msg)
	if !ok || rcode != 5 || ancount != 7 {
		t.Errorf("headerCounts = %d, %d, %v", rcode, ancount, ok)
	}
	if _, _, ok := headerCounts([]byte{1, 2, 3}); ok {
		t.Error("headerCounts accepted a short message")
	}
}
