//go:build windows

package trace

import (
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The IP Helper API lets us send raw ICMP echoes with a chosen TTL from an
// unprivileged process — the standard trick for no-admin traceroute on Windows.
var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

// ICMP status codes returned in ICMP_ECHO_REPLY.Status (ipexport.h).
const (
	ipSuccess           = 0
	ipTTLExpiredTransit = 11013
)

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

// probeHop sends one ICMP echo to dst with the given TTL and reports who
// answered. A timeout is returned as a nil-from reply (loss), not an error.
func probeHop(dst net.IP, ttl int, timeout time.Duration) hopReply {
	dst4 := dst.To4()
	if dst4 == nil {
		return hopReply{err: net.InvalidAddrError("нужен IPv4-адрес")}
	}

	h, _, _ := procIcmpCreate.Call()
	if h == 0 || h == uintptr(^uintptr(0)) {
		return hopReply{err: windows.GetLastError()}
	}
	defer procIcmpClose.Call(h)

	dstAddr := uint32(dst4[0]) | uint32(dst4[1])<<8 | uint32(dst4[2])<<16 | uint32(dst4[3])<<24

	req := []byte("speedtest-trace")
	opts := ipOptionInformation{TTL: uint8(ttl)}

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
		// No reply within the timeout: treat as loss for this hop.
		return hopReply{}
	}

	er := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	from := net.IPv4(byte(er.Address), byte(er.Address>>8), byte(er.Address>>16), byte(er.Address>>24))
	rtt := time.Duration(er.RoundTripTime) * time.Millisecond

	switch er.Status {
	case ipSuccess:
		return hopReply{from: from, rtt: rtt, reached: true}
	case ipTTLExpiredTransit:
		return hopReply{from: from, rtt: rtt}
	default:
		// Some intermediate error (host/net unreachable): still a hop that
		// answered, but not the destination.
		if from.Equal(net.IPv4(0, 0, 0, 0)) {
			return hopReply{}
		}
		return hopReply{from: from, rtt: rtt}
	}
}
