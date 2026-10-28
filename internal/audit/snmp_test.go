package audit

import "testing"

// buildSNMPGet must produce a well-formed SNMPv1 message: outer SEQUENCE,
// version=0, the community string, and a GetRequest PDU.
func TestBuildSNMPGet(t *testing.T) {
	pkt := buildSNMPGet("public")
	if pkt[0] != 0x30 {
		t.Fatalf("packet does not start with SEQUENCE tag: %#x", pkt[0])
	}
	// length byte must equal the remaining bytes (short-form encoding).
	if int(pkt[1]) != len(pkt)-2 {
		t.Errorf("length byte %d != body %d", pkt[1], len(pkt)-2)
	}
	if !containsSub(pkt, []byte("public")) {
		t.Error("community string not present in packet")
	}
	// version varbind 0x02 0x01 0x00 (INTEGER 0) must appear.
	if !containsSub(pkt, []byte{0x02, 0x01, 0x00}) {
		t.Error("SNMPv1 version marker missing")
	}
	// GetRequest PDU tag 0xa0.
	if !containsSub(pkt, []byte{0xa0}) {
		t.Error("GetRequest PDU tag missing")
	}
}

func TestBuildSNMPGetCommunityLength(t *testing.T) {
	pkt := buildSNMPGet("private")
	// community OCTET STRING tag 0x04 followed by its length 7.
	idx := indexSub(pkt, []byte{0x04, 0x07})
	if idx < 0 {
		t.Fatal("community TLV with length 7 not found")
	}
}

// snmpIsResponse must accept a well-formed GetResponse that echoes the
// community, and reject payloads that merely contain byte 0xa2 or a wrong
// community — the false positives the old byte-scan check produced.
func TestSNMPIsResponse(t *testing.T) {
	// SEQUENCE { INTEGER 0, OCTET STRING "public", 0xa2 <getresponse> }
	pdu := tlv(0xa2, []byte{0x02, 0x01, 0x00}) // minimal GetResponse body
	body := concat([]byte{0x02, 0x01, 0x00}, tlv(0x04, []byte("public")), pdu)
	good := tlv(0x30, body)
	if !snmpIsResponse(good, "public") {
		t.Error("valid GetResponse rejected")
	}
	// Right structure but the community doesn't match what we sent.
	if snmpIsResponse(good, "private") {
		t.Error("accepted a response echoing a different community")
	}
	// Starts with 0x30 and contains 0xa2, but is not a valid SNMP message.
	junk := []byte{0x30, 0x05, 0xa2, 0x00, 0x11, 0x22, 0x33}
	if snmpIsResponse(junk, "public") {
		t.Error("accepted non-SNMP payload that merely contains 0xa2")
	}
}

func containsSub(b, sub []byte) bool { return indexSub(b, sub) >= 0 }

func indexSub(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
