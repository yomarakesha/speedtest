package audit

import "testing"

// smbV1NegotiateRequest must be a well-formed NetBIOS-wrapped SMBv1 negotiate.
func TestSMBV1NegotiateRequest(t *testing.T) {
	pkt := smbV1NegotiateRequest()

	// NetBIOS header: type 0x00 then 3-byte length that equals the SMB payload.
	if pkt[0] != 0x00 {
		t.Fatalf("NetBIOS type = %#x, want 0x00", pkt[0])
	}
	nbLen := int(pkt[1])<<16 | int(pkt[2])<<8 | int(pkt[3])
	if nbLen != len(pkt)-4 {
		t.Errorf("NetBIOS length %d != payload %d", nbLen, len(pkt)-4)
	}

	smb := pkt[4:]
	if smb[0] != 0xFF || string(smb[1:4]) != "SMB" {
		t.Errorf("bad SMB magic: %#x %q", smb[0], smb[1:4])
	}
	if smb[4] != 0x72 {
		t.Errorf("command = %#x, want 0x72 (negotiate)", smb[4])
	}
	if !containsSub(smb, []byte("NT LM 0.12")) {
		t.Error("dialect NT LM 0.12 missing")
	}
	// Header is 32 bytes; the word-count byte follows it.
	if smb[32] != 0x00 {
		t.Errorf("word count = %#x, want 0 for negotiate request", smb[32])
	}
}
