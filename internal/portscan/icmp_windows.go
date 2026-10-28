//go:build windows

package portscan

import (
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The IP Helper API sends ICMP echoes from an unprivileged process, so the
// liveness sweep needs no administrator rights (same trick as the traceroute).
var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

// ipSuccess is ICMP_ECHO_REPLY.Status for a host that answered (ipexport.h).
const ipSuccess = 0

// ipOptionInformation mirrors the Win32 IP_OPTION_INFORMATION struct. The
// trailing pointer forces 8-byte alignment on amd64, matching the C layout.
type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors the Win32 ICMP_ECHO_REPLY struct (amd64 layout).
type icmpEchoReply struct {
	Address       uint32 // IPv4 of the responder, network byte order
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// icmpAlive reports whether host answers an ICMP echo within timeout. Any
// failure (bad address, API unavailable) is reported as "not alive" — the TCP
// probes still get their say.
func icmpAlive(host string, timeout time.Duration) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	dst4 := ip.To4()
	if dst4 == nil {
		return false
	}

	h, _, _ := procIcmpCreate.Call()
	if h == 0 || h == uintptr(^uintptr(0)) {
		return false
	}
	defer procIcmpClose.Call(h)

	dstAddr := uint32(dst4[0]) | uint32(dst4[1])<<8 | uint32(dst4[2])<<16 | uint32(dst4[3])<<24

	req := []byte("speedtest-ping")
	opts := ipOptionInformation{TTL: 128}

	// Reply buffer: one ICMP_ECHO_REPLY + the echoed request + slack, per the
	// IcmpSendEcho contract (MSDN recommends reply struct + 8 bytes minimum).
	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(req) + 8
	reply := make([]byte, replySize)

	ret, _, _ := procIcmpSendEcho.Call(
		h,
		uintptr(dstAddr),
		uintptr(unsafe.Pointer(&req[0])),
		uintptr(uint16(len(req))),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(uint32(replySize)),
		uintptr(uint32(timeout.Milliseconds())),
	)
	if ret == 0 {
		return false // no reply within the timeout
	}

	er := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	// Only an echo reply from the target itself proves it is up; "host
	// unreachable" from a router carries a different status.
	return er.Status == ipSuccess && er.Address == dstAddr
}
