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
