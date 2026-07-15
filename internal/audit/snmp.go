package audit

import (
	"net"
	"slices"
	"time"
)

// defaultCommunities are the factory-default SNMP community strings tried by the
// UDP/161 check. A device that answers any of them exposes its config (and, for
// "private", write access) to anyone on the network.
var defaultCommunities = []string{"public", "private", "manager", "cisco", "admin"}

// AuditSNMP checks UDP/161 for a device that answers a default community string.
// It speaks just enough SNMPv1 to send a single GET for sysDescr.0 and see
// whether a valid response comes back. host is a bare IP or hostname.
func AuditSNMP(host string, timeout time.Duration) []Finding {
	addr := net.JoinHostPort(host, "161")
	var out []Finding
	for _, community := range defaultCommunities {
		if snmpAnswers(addr, community, timeout) {
			sev := High
			if community == "private" {
				sev = Critical // write community — device reconfiguration
			}
			out = append(out, Finding{
				Check:    "snmp.default_community",
				Severity: sev,
				Title:    "SNMP отвечает на стандартную community-строку",
				Detail:   "community: " + community + " (UDP/161)",
				Evidence: community,
			})
			return out // one hit is enough; stop probing this host
		}
	}
	return out
}

// snmpAnswers sends an SNMPv1 GET for sysDescr.0 with the given community and
// reports whether a well-formed SNMP response returns.
func snmpAnswers(addr, community string, timeout time.Duration) bool {
	req := buildSNMPGet(community)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	// A response is an SNMP message (SEQUENCE, tag 0x30) carrying a GetResponse
	// PDU (tag 0xa2). Seeing both is a strong signal the community was accepted.
	resp := buf[:n]
	return len(resp) > 2 && resp[0] == 0x30 && slices.Contains(resp, 0xa2)
}

// buildSNMPGet hand-encodes a minimal SNMPv1 GetRequest for sysDescr.0
// (1.3.6.1.2.1.1.1.0). Building the ~40-byte packet by hand avoids pulling in
// an ASN.1/SNMP dependency for a single probe.
func buildSNMPGet(community string) []byte {
	// Varbind: OID sysDescr.0 with a NULL value.
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	varbind := tlv(0x30, append(append([]byte{}, oid...), 0x05, 0x00))
	varbindList := tlv(0x30, varbind)

	// GetRequest PDU: request-id, error-status, error-index, varbind list.
	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIndex := []byte{0x02, 0x01, 0x00}
	pduBody := concat(reqID, errStatus, errIndex, varbindList)
	pdu := tlv(0xa0, pduBody) // 0xa0 = GetRequest

	version := []byte{0x02, 0x01, 0x00} // SNMPv1
	comm := tlv(0x04, []byte(community))
	msgBody := concat(version, comm, pdu)
	return tlv(0x30, msgBody)
}

// tlv wraps content in an ASN.1 tag-length-value. Length is limited to the
// short form (<128 bytes), which is ample for this fixed probe.
func tlv(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+2)
	out = append(out, tag, byte(len(content)))
	return append(out, content...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
