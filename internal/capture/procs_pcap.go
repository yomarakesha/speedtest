//go:build pcap

package capture

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// pidLookup and procName are populated by the platform-specific attribution
// backend (currently pidlookup_windows_pcap.go, windows && pcap only). Left
// nil on platforms without one, so TopProcesses reports ErrUnavailable there
// instead of running a monitor that can never attribute anything.
var (
	pidLookup func(proto string, port uint16) (pid int, ok bool)
	procName  func(pid int) string
)

// TopProcesses opens opt.Iface, tallies bytes per local process over each
// opt.Interval window, and calls cb with the ranking until ctx is cancelled.
// Traffic that can't be attributed to a known process lands in the PID-0
// "Система/неизвестно" bucket. Requires a platform attribution backend
// (Windows only for now) — returns ErrUnavailable where none is compiled in.
func TopProcesses(ctx context.Context, opt Options, cb func([]ProcTraffic)) error {
	if pidLookup == nil {
		return ErrUnavailable
	}

	handle, err := openCapture(opt.Iface)
	if err != nil {
		return err
	}
	defer handle.Close()

	interval := opt.Interval
	if interval <= 0 {
		interval = time.Second
	}

	local := localIPSet()
	acc := newProcessAccumulator(local, pidLookup, procName)
	lastTick := time.Now()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			cb(acc.rates(opt.Top, now.Sub(lastTick).Seconds()))
			acc = newProcessAccumulator(local, pidLookup, procName)
			lastTick = now
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			observeProcPacket(acc, pkt)
		}
	}
}

// observeProcPacket decodes one frame's IP/TCP/UDP headers and credits it to
// the accumulator. Non-IP frames are skipped; non-TCP/UDP IP frames (ICMP,
// etc.) go to the unattributed bucket via observeOther.
func observeProcPacket(acc *processAccumulator, pkt gopacket.Packet) {
	var srcIP, dstIP string
	switch net := pkt.NetworkLayer(); l := net.(type) {
	case *layers.IPv4:
		srcIP, dstIP = l.SrcIP.String(), l.DstIP.String()
	case *layers.IPv6:
		srcIP, dstIP = l.SrcIP.String(), l.DstIP.String()
	default:
		_ = l
		return
	}

	length := len(pkt.Data())
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		acc.observe("tcp", srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort), length)
		return
	}
	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		acc.observe("udp", srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), length)
		return
	}
	acc.observeOther(srcIP, dstIP, length)
}
