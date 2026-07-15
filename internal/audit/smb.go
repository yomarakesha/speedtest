package audit

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

// AuditSMB checks TCP/445 for an enabled SMBv1 dialect. SMBv1 is the protocol
// exploited by EternalBlue (MS17-010) and WannaCry; a host that still negotiates
// it exposes a large, well-known attack surface and should disable it. host is a
// bare IP or hostname.
func AuditSMB(host string, timeout time.Duration) []Finding {
	if !smbV1Enabled(net.JoinHostPort(host, "445"), timeout) {
		return nil
	}
	return []Finding{{
		Check:    "smb.v1_enabled",
		Severity: High,
		Title:    "Включён протокол SMBv1 (поверхность EternalBlue/MS17-010)",
		Detail:   "сервер согласовал устаревший диалект SMBv1 (NT LM 0.12); отключите SMBv1",
		Evidence: "NT LM 0.12",
	}}
}

// smbV1Enabled sends an SMBv1 SMB_COM_NEGOTIATE offering only the "NT LM 0.12"
// dialect and reports whether the server accepts it. A server with SMBv1
// disabled either resets, answers with SMB2 (0xFE 'SMB'), or returns a dialect
// index of 0xFFFF meaning "none of the offered dialects".
func smbV1Enabled(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(smbV1NegotiateRequest()); err != nil {
		return false
	}

	// NetBIOS session header: 1 type byte + 3 length bytes, then the SMB message.
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return false
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < 33 || n > 4096 { // SMBv1 header is 32 bytes + at least a word count
		return false
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return false
	}

	// Must be an SMBv1 response (0xFF 'S' 'M' 'B') to the negotiate command 0x72.
	if len(msg) < 37 || msg[0] != 0xFF || string(msg[1:4]) != "SMB" || msg[4] != 0x72 {
		return false
	}
	// Parameter block starts after the 32-byte header: 1 word-count byte, then
	// the 2-byte dialect index. 0xFFFF means no offered dialect was accepted.
	wordCount := msg[32]
	if wordCount == 0 {
		return false
	}
	dialectIndex := binary.LittleEndian.Uint16(msg[33:35])
	return dialectIndex != 0xFFFF
}

// smbV1NegotiateRequest builds the classic SMBv1 negotiate packet offering the
// single "NT LM 0.12" dialect, wrapped in a NetBIOS session message.
func smbV1NegotiateRequest() []byte {
	// SMBv1 header (32 bytes): magic, command, status, flags, and zeroed IDs.
	header := []byte{
		0xFF, 'S', 'M', 'B', // protocol
		0x72,                   // SMB_COM_NEGOTIATE
		0x00, 0x00, 0x00, 0x00, // NT status: success
		0x18,       // flags
		0x53, 0xC8, // flags2
		0x00, 0x00, // PID high
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
		0x00, 0x00, // reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID
		0x00, 0x00, // UID
		0x00, 0x00, // MID
	}
	// Body: word count 0, then a byte count and the dialect entry.
	dialect := append([]byte{0x02}, []byte("NT LM 0.12\x00")...) // 0x02 = dialect marker
	body := []byte{0x00} // WordCount
	body = append(body, byte(len(dialect)), 0x00)
	body = append(body, dialect...)

	smb := append(header, body...)

	// NetBIOS session message header: type 0x00 + 3-byte big-endian length.
	nb := []byte{0x00, byte(len(smb) >> 16), byte(len(smb) >> 8), byte(len(smb))}
	return append(nb, smb...)
}
