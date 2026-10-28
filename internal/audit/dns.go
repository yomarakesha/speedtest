package audit

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// AuditDNS checks a host that may be a DNS server for two classic weaknesses:
// acting as an open recursive resolver, and allowing unauthenticated zone
// transfers (AXFR). host may be an IP or a domain name; when it is a domain the
// AXFR check asks it to transfer its own zone.
func AuditDNS(host string, timeout time.Duration) []Finding {
	server := hostForDNS(host)
	var out []Finding
	if f := openResolverFinding(net.JoinHostPort(server, "53"), timeout); f != nil {
		out = append(out, *f)
	}
	if isDomain(host) {
		if f := axfrFinding(net.JoinHostPort(server, "53"), host, timeout); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// openResolverFinding sends a recursive query for an unrelated public name to
// the DNS server at addr (host:port) and reports a finding if the server
// answers it (i.e. resolves for strangers).
func openResolverFinding(addr string, timeout time.Duration) *Finding {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("example.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(packed); err != nil {
		return nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil // no DNS service here, or it declined — not open
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil
	}
	if resp.RecursionAvailable && resp.RCode == dnsmessage.RCodeSuccess && len(resp.Answers) > 0 {
		return &Finding{
			Check: "dns.open_resolver", Severity: High,
			Title:  "Открытый рекурсивный DNS-резолвер",
			Detail: "отвечает на рекурсивные запросы извне (риск усиления DDoS)",
		}
	}
	return nil
}

// axfrFinding attempts a zone transfer of zone from the server at addr
// (host:port); a server that returns records to an unauthenticated client leaks
// its entire zone.
func axfrFinding(addr, zone string, timeout time.Duration) *Finding {
	name, err := dnsmessage.NewName(dnsName(zone))
	if err != nil {
		return nil
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypeAXFR, Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// AXFR over TCP is length-prefixed with a 2-byte big-endian length.
	framed := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(framed, uint16(len(packed)))
	copy(framed[2:], packed)
	if _, err := conn.Write(framed); err != nil {
		return nil
	}

	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(respBuf); err != nil {
		return nil
	}
	if resp.RCode == dnsmessage.RCodeSuccess && len(resp.Answers) > 0 {
		return &Finding{
			Check: "dns.axfr_allowed", Severity: High,
			Title:    "Разрешён перенос зоны (AXFR)",
			Detail:   "сервер отдаёт полную зону неаутентифицированному клиенту",
			Evidence: zone,
		}
	}
	return nil
}

// hostForDNS strips a scheme/port/path, leaving a bare host or IP to query.
func hostForDNS(target string) string { return HostOnly(target) }

// dnsName ensures a fully-qualified, dot-terminated name for a zone query.
func dnsName(zone string) string {
	zone = HostOnly(zone)
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

// isDomain reports whether target looks like a hostname (not a bare IP), so an
// AXFR by zone name makes sense.
func isDomain(target string) bool {
	h := HostOnly(target)
	return net.ParseIP(h) == nil && strings.Contains(h, ".")
}
