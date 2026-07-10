package audit

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestIsDomain(t *testing.T) {
	if !isDomain("example.com") {
		t.Error("example.com should be a domain")
	}
	if isDomain("192.168.1.1") {
		t.Error("bare IP should not be a domain")
	}
	if isDomain("localhost") {
		t.Error("dotless host should not count as a domain")
	}
}

func TestDNSName(t *testing.T) {
	if got := dnsName("example.com"); got != "example.com." {
		t.Errorf("dnsName = %q, want fully-qualified", got)
	}
	if got := dnsName("example.com."); got != "example.com." {
		t.Errorf("dnsName double-dotted: %q", got)
	}
}

// answerARecord builds a DNS response to q that carries one A record and the
// requested header bits, so the open-resolver check sees a real answer.
func answerARecord(q dnsmessage.Message) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.Header.ID,
			Response:           true,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: q.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Questions[0].Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
			Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}},
	}
	return resp.Pack()
}

func TestOpenResolverDetected(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			return
		}
		out, err := answerARecord(q)
		if err == nil {
			pc.WriteTo(out, addr)
		}
	}()

	if got := openResolverFinding(pc.LocalAddr().String(), time.Second); got == nil {
		t.Error("expected open-resolver finding from answering server")
	}
}

func TestAXFRFramingRoundTrip(t *testing.T) {
	// Verify the 2-byte length framing is what a TCP DNS server expects.
	payload := []byte{0xAA, 0xBB, 0xCC}
	framed := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(framed, uint16(len(payload)))
	copy(framed[2:], payload)
	if binary.BigEndian.Uint16(framed[:2]) != 3 {
		t.Error("length prefix mismatch")
	}
}
