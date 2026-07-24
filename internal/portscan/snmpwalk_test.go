package portscan

import (
	"slices"
	"testing"
)

func TestEncodeDecodeOIDRoundTrip(t *testing.T) {
	cases := [][]int{
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 3},
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 192, 168, 1, 1},
		{1, 3, 6, 1, 4, 1, 9, 2, 128}, // multi-byte sub-identifier (128 > 127)
		{2, 5, 300, 1},                // large component crossing the base-128 boundary
	}
	for _, oid := range cases {
		enc := encodeOID(oid)
		// enc is a full TLV; strip the tag+len to get the body decodeOID expects.
		body, _, ok := snmpReadTLV(enc, 0x06)
		if !ok {
			t.Fatalf("encodeOID(%v) produced a bad TLV", oid)
		}
		got, ok := decodeOID(body)
		if !ok || !slices.Equal(got, oid) {
			t.Errorf("roundtrip %v: got %v (ok=%v)", oid, got, ok)
		}
	}
}

// buildFakeResponse hand-builds an SNMPv1 GetResponse carrying a single varbind
// (oid, IpAddress value) so the parser and snmpSubnets can be tested offline.
func buildFakeResponse(community string, oid []int, ipVal []byte) []byte {
	varbind := snmpTLV(0x30, snmpConcat(encodeOID(oid), snmpTLV(0x40, ipVal))) // 0x40 = IpAddress
	vbList := snmpTLV(0x30, varbind)
	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIndex := []byte{0x02, 0x01, 0x00}
	pdu := snmpTLV(0xa2, snmpConcat(reqID, errStatus, errIndex, vbList)) // 0xa2 = GetResponse
	version := []byte{0x02, 0x01, 0x00}
	comm := snmpTLV(0x04, []byte(community))
	return snmpTLV(0x30, snmpConcat(version, comm, pdu))
}

func TestParseSNMPVar(t *testing.T) {
	oid := append(slices.Clone(ipAdEntNetMaskOID), 192, 168, 20, 1)
	mask := []byte{255, 255, 255, 0}
	resp := buildFakeResponse("public", oid, mask)

	v, ok := parseSNMPVar(resp, "public")
	if !ok {
		t.Fatal("parseSNMPVar failed on a well-formed response")
	}
	if !slices.Equal(v.oid, oid) {
		t.Errorf("oid = %v, want %v", v.oid, oid)
	}
	if !slices.Equal(v.val, mask) {
		t.Errorf("val = %v, want %v", v.val, mask)
	}

	// Wrong community must be rejected (guards against stray UDP).
	if _, ok := parseSNMPVar(resp, "private"); ok {
		t.Error("parseSNMPVar accepted a mismatched community")
	}
}

func TestHopSubnet(t *testing.T) {
	cases := map[string]string{
		"10.20.0.1":     "10.20.0.0/24",
		"192.168.100.5": "192.168.100.0/24",
		"127.0.0.1":     "", // loopback dropped
		"224.0.0.1":     "", // multicast dropped
		"":              "", // timed-out hop
		"not-an-ip":     "",
	}
	for in, want := range cases {
		if got := hopSubnet(in); got != want {
			t.Errorf("hopSubnet(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRouterGuesses(t *testing.T) {
	got := routerGuesses("192.168.1.0/24")
	want := []string{"192.168.1.1", "192.168.1.254"}
	if !slices.Equal(got, want) {
		t.Errorf("routerGuesses(/24) = %v, want %v", got, want)
	}
	if g := routerGuesses("10.0.0.0/8"); !slices.Equal(g, []string{"10.0.0.1", "10.255.255.254"}) {
		t.Errorf("routerGuesses(/8) = %v", g)
	}
	if g := routerGuesses("192.168.1.0/31"); g != nil {
		t.Errorf("routerGuesses(/31) = %v, want nil (too small)", g)
	}
}
