//go:build !windows

package portscan

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// protocolICMP is the IANA protocol number for ICMP (used by ParseMessage).
const protocolICMP = 1

// icmpAlive reports whether host answers an ICMP echo within timeout. It uses
// an unprivileged ICMP datagram socket (no root needed on Linux/macOS); if the
// kernel refuses such sockets the probe simply reports "not alive" and the TCP
// probes decide.
func icmpAlive(host string, timeout time.Duration) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	dst4 := ip.To4()
	if dst4 == nil {
		return false
	}

	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			// The kernel rewrites ID on unprivileged sockets, so replies are
			// demultiplexed per socket — one socket per probe keeps that simple.
			ID: 1, Seq: 1,
			Data: []byte("speedtest-ping"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return false
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: dst4}); err != nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	rb := make([]byte, 1500)
	for {
		if err := c.SetReadDeadline(deadline); err != nil {
			return false
		}
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return false // timeout: no answer
		}
		ua, ok := peer.(*net.UDPAddr)
		if !ok || !ua.IP.Equal(dst4) {
			continue // an unrelated responder (e.g. a router error): keep waiting
		}
		rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return true
		}
	}
}
