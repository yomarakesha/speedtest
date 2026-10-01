package wol

import "testing"

func TestParseMAC(t *testing.T) {
	want := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	cases := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"aabbccddeeff",
		"AABBCCDDEEFF",
	}
	for _, in := range cases {
		got, err := ParseMAC(in)
		if err != nil {
			t.Fatalf("ParseMAC(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseMAC(%q) = %x, want %x", in, got, want)
		}
	}
}

func TestParseMACInvalid(t *testing.T) {
	cases := []string{
		"",
		"aa:bb:cc:dd:ee",
		"aa:bb:cc:dd:ee:ff:00",
		"zz:bb:cc:dd:ee:ff",
	}
	for _, in := range cases {
		if _, err := ParseMAC(in); err == nil {
			t.Errorf("ParseMAC(%q) expected error, got nil", in)
		}
	}
}

func TestBuildPacket(t *testing.T) {
	p, err := BuildPacket("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("BuildPacket: unexpected error: %v", err)
	}
	if len(p) != 102 {
		t.Fatalf("len(packet) = %d, want 102", len(p))
	}
	for i := 0; i < 6; i++ {
		if p[i] != 0xFF {
			t.Errorf("byte %d = %x, want 0xFF", i, p[i])
		}
	}
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for rep := 0; rep < 16; rep++ {
		for j := 0; j < 6; j++ {
			off := 6 + rep*6 + j
			if p[off] != mac[j] {
				t.Errorf("byte %d (rep %d, pos %d) = %x, want %x", off, rep, j, p[off], mac[j])
			}
		}
	}
}

func TestBuildPacketInvalid(t *testing.T) {
	if _, err := BuildPacket("not-a-mac"); err == nil {
		t.Error("BuildPacket with invalid MAC: expected error, got nil")
	}
}
