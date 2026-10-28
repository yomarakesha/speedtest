//go:build !windows && !linux

package trace

import (
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// protocolICMP is the IANA protocol number for ICMP (used by ParseMessage).
const protocolICMP = 1

// probeHop sends one ICMP echo with the given TTL over an unprivileged datagram
// socket (no root needed on Linux/macOS) and reports who answered. A timeout is
// a nil-from reply (loss), not an error.
func probeHop(dst net.IP, ttl int, timeout time.Duration) hopReply {
	dst4 := dst.To4()
	if dst4 == nil {
		return hopReply{err: net.InvalidAddrError("нужен IPv4-адрес")}
	}

	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return hopReply{err: err}
	}
	defer c.Close()

	if err := c.IPv4PacketConn().SetTTL(ttl); err != nil {
		return hopReply{err: err}
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: ttl,
			Data: []byte("speedtest-trace"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return hopReply{err: err}
	}

	start := time.Now()
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: dst4}); err != nil {
		return hopReply{err: err}
	}

	_ = c.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return hopReply{} // timeout: loss for this hop
	}
	rtt := time.Since(start)

	rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
	if err != nil {
		return hopReply{}
	}

	var from net.IP
	if ua, ok := peer.(*net.UDPAddr); ok {
		from = ua.IP
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return hopReply{from: from, rtt: rtt, reached: true}
	case ipv4.ICMPTypeTimeExceeded:
		return hopReply{from: from, rtt: rtt}
	default:
		return hopReply{from: from, rtt: rtt}
	}
}
