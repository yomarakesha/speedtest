package portscan

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"
)

// UDPState is the verdict for a scanned UDP port. UDP is connectionless, so
// unlike TCP the three outcomes cannot always be told apart: a service that
// answers is definitely open, an ICMP port-unreachable proves closed, and
// silence could mean either an open service that ignores our probe or a firewall
// dropping the packet.
type UDPState string

const (
	UDPOpen     UDPState = "open"          // a reply came back
	UDPClosed   UDPState = "closed"        // ICMP port-unreachable
	UDPFiltered UDPState = "open|filtered" // silence: open service or dropped
)

// UDPResult is the outcome of probing one UDP port.
type UDPResult struct {
	Port    int      `json:"port"`
	Service string   `json:"service,omitempty"`
	State   UDPState `json:"state"`
	Reply   string   `json:"reply,omitempty"` // short hex of the first bytes returned
}

// udpProbe is a service-specific payload sent to elicit a reply. A blank payload
// still detects "closed" via ICMP, but a real service query is what turns
// silence into a confident "open".
type udpProbe struct {
	service string
	payload []byte
}

// udpProbes maps a UDP port to the packet most likely to make its service talk.
// Each payload is a minimal, read-only query for that protocol.
var udpProbes = map[int]udpProbe{
	53:   {"dns", dnsQuery()},                                        // standard A query for version.bind
	123:  {"ntp", ntpQuery()},                                        // mode 3 client request
	161:  {"snmp", snmpGetRequest()},                                 // GET sysDescr, community "public"
	137:  {"netbios", nbnsQuery()},                                   // node status request
	138:  {"netbios-dgm", []byte{0x00}},                              //
	500:  {"ike", ikeSA()},                                           // ISAKMP main-mode SA proposal
	1900: {"ssdp", ssdpQuery()},                                      // M-SEARCH discovery
	5353: {"mdns", mdnsQuery()},                                      // multicast DNS PTR query
	69:   {"tftp", []byte{0, 1, 'a', 0, 'o', 'c', 't', 'e', 't', 0}}, // read request
	111:  {"rpcbind", rpcNull()},                                     // portmapper NULL call
	1194: {"openvpn", []byte{0x38, 0, 0, 0, 0, 0, 0, 0, 0}},          // control hard-reset
}

// commonUDPPorts is the default set scanned when no spec is given: the UDP
// services worth knowing about on a host or LAN.
var commonUDPPorts = []int{53, 67, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353}

// ScanUDP probes the given UDP ports on host and returns each port's state,
// sorted by port. workers bounds concurrency. A name is resolved once by the
// caller; host here is an address.
func ScanUDP(ctx context.Context, host string, ports []int, timeout time.Duration, workers int) []UDPResult {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	results := make([]UDPResult, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = UDPResult{Port: port, State: UDPFiltered}
				return
			}
			results[i] = probeUDP(host, port, timeout)
		}(i, p)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

// probeUDP sends the service probe for a port (an empty datagram when none is
// known) and classifies the outcome. A reply means open; an ICMP-driven
// ECONNREFUSED on read means closed; a timeout means open|filtered.
func probeUDP(host string, port int, timeout time.Duration) UDPResult {
	svc := ""
	payload := []byte{0}
	if pr, ok := udpProbes[port]; ok {
		svc, payload = pr.service, pr.payload
	}
	res := UDPResult{Port: port, Service: svc, State: UDPFiltered}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return res
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return res
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	switch {
	case err == nil:
		res.State = UDPOpen
		if n > 0 {
			res.Reply = shortHex(buf[:n])
		}
	case isUDPRefused(err):
		res.State = UDPClosed
	default:
		// A timeout on a silent port is the ambiguous open|filtered case already
		// set. Anything else (network error) is treated the same way.
	}
	return res
}

// isUDPRefused reports an ICMP port-unreachable surfaced as a socket error.
// Reused isRefused already covers ECONNREFUSED; this keeps the intent named for
// UDP where the same errno means "closed", not "actively refused connection".
func isUDPRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || isRefused(err)
}

// shortHex renders the first bytes of a reply as hex for evidence, capped so a
// chatty service can't flood the output.
func shortHex(b []byte) string {
	const max = 16
	if len(b) > max {
		b = b[:max]
	}
	return hex.EncodeToString(b)
}

// --- Service probe payloads. Each is a minimal, read-only request. ---

// dnsQuery builds a standard recursive A-record query for a common name. A real
// A/IN query is answered by every resolver — authoritative or recursive, and
// even a refusal is a datagram — so it reliably proves the port is open, unlike
// a version.bind CHAOS probe that hardened resolvers drop silently.
func dnsQuery() []byte {
	return []byte{
		0x12, 0x34, // transaction ID
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // 1 question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // end of name
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}
}

// ntpQuery builds a mode-3 (client) NTP request; any NTP server replies.
func ntpQuery() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b // LI=0, VN=3, Mode=3
	return b
}

// snmpGetRequest builds an SNMPv1 GET of sysDescr.0 with community "public".
func snmpGetRequest() []byte {
	return []byte{
		0x30, 0x26, // SEQUENCE
		0x02, 0x01, 0x00, // version 1 (0)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community
		0xa0, 0x19, // GET request PDU
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request id
		0x02, 0x01, 0x00, // error status
		0x02, 0x01, 0x00, // error index
		0x30, 0x0b, // varbind list
		0x30, 0x09, // varbind
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1 (sysDescr prefix)
		0x05, 0x00, // NULL value
	}
}

// nbnsQuery builds a NetBIOS node-status request ("*" name), which Windows and
// Samba answer with the machine's names.
func nbnsQuery() []byte {
	return []byte{
		0x80, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00, 0x00, 0x21, 0x00, 0x01,
	}
}

// ssdpQuery builds an SSDP M-SEARCH discovery datagram; UPnP devices reply.
func ssdpQuery() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n")
}

// mdnsQuery builds a multicast-DNS PTR query for the service-enumeration name.
func mdnsQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00, 0x00, 0x0c, 0x00, 0x01,
	}
}

// ikeSA builds a minimal ISAKMP main-mode SA proposal; VPN gateways reply.
func ikeSA() []byte {
	return []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // initiator cookie
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder cookie (zero)
		0x01,                   // next payload: SA
		0x10,                   // version 1.0
		0x02,                   // exchange type: identity protection (main mode)
		0x00,                   // flags
		0x00, 0x00, 0x00, 0x00, // message ID
		0x00, 0x00, 0x00, 0x1c, // length
	}
}

// rpcNull builds a portmapper (rpcbind) NULL procedure call over UDP.
func rpcNull() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x01, // XID
		0x00, 0x00, 0x00, 0x00, // call
		0x00, 0x00, 0x00, 0x02, // RPC version 2
		0x00, 0x01, 0x86, 0xa0, // program 100000 (portmap)
		0x00, 0x00, 0x00, 0x02, // program version 2
		0x00, 0x00, 0x00, 0x00, // procedure 0 (NULL)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // null auth
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // null verifier
	}
}
