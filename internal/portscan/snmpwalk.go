package portscan

import (
	"fmt"
	"net"
	"time"
)

// SNMP subnet discovery: an SNMPv1 GETNEXT walk of a gateway's ipAddrTable to
// learn every subnet the router is directly attached to. This reveals sibling
// subnets that are invisible to the local machine's own routing table (the whole
// point of --expand). Best-effort and read-only: a closed agent or wrong
// community simply yields no subnets. The tiny ASN.1 codec here mirrors the
// single-GET probe in the audit package but adds OID encoding and a walk loop.

// ipAdEntNetMaskOID is the root of ipAddrTable's netmask column
// (1.3.6.1.2.1.4.20.1.3). A walk returns one entry per router interface: the
// OID's trailing 4 sub-identifiers are the interface IP, the value is its mask.
var ipAdEntNetMaskOID = []int{1, 3, 6, 1, 2, 1, 4, 20, 1, 3}

// snmpVar is one (OID, value) pair returned by a walk.
type snmpVar struct {
	oid []int
	val []byte
	tag byte
}

// snmpSubnets walks the gateway's interface table over SNMPv1 and returns the
// CIDRs it is directly attached to (deduplicated, filtered to real LAN subnets).
// timeout bounds each request; the whole walk is capped to avoid a runaway agent.
func snmpSubnets(gateway, community string, timeout time.Duration) []string {
	addr := net.JoinHostPort(gateway, "161")
	vars := snmpWalk(addr, community, ipAdEntNetMaskOID, timeout, 256)

	seen := map[string]bool{}
	var out []string
	for _, v := range vars {
		// The interface IP is the 4 sub-identifiers appended after the root OID.
		if len(v.oid) < len(ipAdEntNetMaskOID)+4 || len(v.val) != 4 {
			continue
		}
		ipParts := v.oid[len(v.oid)-4:]
		ip := net.IPv4(byte(ipParts[0]), byte(ipParts[1]), byte(ipParts[2]), byte(ipParts[3])).To4()
		mask := net.IPv4Mask(v.val[0], v.val[1], v.val[2], v.val[3])
		ones, bits := mask.Size()
		if bits != 32 { // non-contiguous mask
			continue
		}
		cidr := fmt.Sprintf("%s/%d", ip.Mask(mask).String(), ones)
		if seen[cidr] || !usefulSubnet(cidr) {
			continue
		}
		seen[cidr] = true
		out = append(out, cidr)
	}
	return out
}

// snmpWalk performs an SNMPv1 GETNEXT walk of the subtree rooted at root over
// UDP/161, returning every (OID, value) pair whose OID stays within root. It
// stops on the first transport/parse error, when the subtree is exhausted, or
// after max variables (a guard against a misbehaving agent).
func snmpWalk(addr, community string, root []int, timeout time.Duration, max int) []snmpVar {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	var out []snmpVar
	cur := root
	for range max {
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(buildSNMPGetNext(community, cur)); err != nil {
			return out
		}
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return out
		}
		v, ok := parseSNMPVar(buf[:n], community)
		if !ok || !oidHasPrefix(v.oid, root) {
			return out // left the subtree (or unparseable) — walk done
		}
		if v.tag == 0x80 || v.tag == 0x82 { // noSuchObject/endOfMibView
			return out
		}
		out = append(out, v)
		cur = v.oid
	}
	return out
}

// oidHasPrefix reports whether oid begins with prefix.
func oidHasPrefix(oid, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}

// buildSNMPGetNext hand-encodes an SNMPv1 GetNextRequest (PDU tag 0xa1) for a
// single varbind naming oid with a NULL value.
func buildSNMPGetNext(community string, oid []int) []byte {
	varbind := snmpTLV(0x30, append(encodeOID(oid), 0x05, 0x00)) // OID + NULL
	varbindList := snmpTLV(0x30, varbind)

	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIndex := []byte{0x02, 0x01, 0x00}
	pdu := snmpTLV(0xa1, snmpConcat(reqID, errStatus, errIndex, varbindList))

	version := []byte{0x02, 0x01, 0x00} // SNMPv1
	comm := snmpTLV(0x04, []byte(community))
	return snmpTLV(0x30, snmpConcat(version, comm, pdu))
}

// parseSNMPVar walks a GetResponse and returns its first varbind's OID, value
// bytes and value tag. community must match to guard against stray UDP.
func parseSNMPVar(resp []byte, community string) (snmpVar, bool) {
	seq, _, ok := snmpReadTLV(resp, 0x30) // outer SEQUENCE
	if !ok {
		return snmpVar{}, false
	}
	_, rest, ok := snmpReadTLV(seq, 0x02) // version
	if !ok {
		return snmpVar{}, false
	}
	comm, rest, ok := snmpReadTLV(rest, 0x04) // community
	if !ok || string(comm) != community {
		return snmpVar{}, false
	}
	pdu, _, ok := snmpReadTLV(rest, 0xa2) // GetResponse PDU
	if !ok {
		return snmpVar{}, false
	}
	// PDU: request-id, error-status, error-index, varbind-list.
	_, prest, ok := snmpReadTLV(pdu, 0x02)
	if !ok {
		return snmpVar{}, false
	}
	_, prest, ok = snmpReadTLV(prest, 0x02)
	if !ok {
		return snmpVar{}, false
	}
	_, prest, ok = snmpReadTLV(prest, 0x02)
	if !ok {
		return snmpVar{}, false
	}
	vbList, _, ok := snmpReadTLV(prest, 0x30)
	if !ok {
		return snmpVar{}, false
	}
	varbind, _, ok := snmpReadTLV(vbList, 0x30)
	if !ok {
		return snmpVar{}, false
	}
	oidBytes, after, ok := snmpReadTLV(varbind, 0x06)
	if !ok {
		return snmpVar{}, false
	}
	oid, ok := decodeOID(oidBytes)
	if !ok {
		return snmpVar{}, false
	}
	if len(after) < 2 { // value TLV follows the OID
		return snmpVar{}, false
	}
	valTag := after[0]
	val, _, ok := snmpReadTLV(after, valTag)
	if !ok {
		return snmpVar{}, false
	}
	return snmpVar{oid: oid, val: val, tag: valTag}, true
}

// encodeOID encodes an OID (as component ints) into ASN.1 OID value bytes,
// wrapped in its TLV. The first two components collapse into 40*a+b; the rest
// are base-128 with the high bit set on all but the final byte.
func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return snmpTLV(0x06, nil)
	}
	body := []byte{byte(40*oid[0] + oid[1])}
	for _, c := range oid[2:] {
		body = append(body, encodeBase128(c)...)
	}
	return snmpTLV(0x06, body)
}

// encodeBase128 encodes one OID sub-identifier in base-128 (MSB continuation).
func encodeBase128(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	var tmp []byte
	for v > 0 {
		tmp = append([]byte{byte(v & 0x7f)}, tmp...)
		v >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

// decodeOID reverses encodeOID's body bytes back into component ints.
func decodeOID(b []byte) ([]int, bool) {
	if len(b) == 0 {
		return nil, false
	}
	oid := []int{int(b[0]) / 40, int(b[0]) % 40}
	v := 0
	for _, c := range b[1:] {
		v = v<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			oid = append(oid, v)
			v = 0
		}
	}
	return oid, true
}

// snmpReadTLV parses one ASN.1 TLV at the start of b whose tag must equal tag,
// returning the value bytes and the bytes following this TLV.
func snmpReadTLV(b []byte, tag byte) (val, rest []byte, ok bool) {
	if len(b) < 2 || b[0] != tag {
		return nil, nil, false
	}
	length := int(b[1])
	i := 2
	if length&0x80 != 0 {
		nbytes := length & 0x7f
		if nbytes == 0 || nbytes > 4 || len(b) < 2+nbytes {
			return nil, nil, false
		}
		length = 0
		for j := range nbytes {
			length = length<<8 | int(b[2+j])
		}
		i = 2 + nbytes
	}
	if length < 0 || len(b) < i+length {
		return nil, nil, false
	}
	return b[i : i+length], b[i+length:], true
}

// snmpTLV wraps content in an ASN.1 tag-length-value, emitting long-form length
// when content is 128 bytes or longer (walk requests stay short, but responses
// we build in tests may not).
func snmpTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	if n < 0x80 {
		out = append(out, byte(n))
	} else if n < 0x100 {
		out = append(out, 0x81, byte(n))
	} else {
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func snmpConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
