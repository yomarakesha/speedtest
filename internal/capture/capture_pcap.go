//go:build pcap

// This file is compiled only with `-tags pcap` and requires gopacket + a pcap
// runtime (Npcap on Windows, libpcap on Linux). Before building:
//
//	go get github.com/google/gopacket
//	go build -tags pcap ./...
//
// It provides passive top-talker accounting. It is intentionally read-only: it
// never injects packets.
package capture

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Available reports that a capture backend is compiled in.
func Available() bool { return true }

// Devices lists capture-capable interfaces via libpcap/Npcap.
func Devices() ([]Device, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(ifs))
	for _, d := range ifs {
		var addrs []string
		for _, a := range d.Addresses {
			if a.IP != nil {
				addrs = append(addrs, a.IP.String())
			}
		}
		out = append(out, Device{Name: d.Name, Description: d.Description, Addrs: addrs})
	}
	return out, nil
}

// TopTalkers opens opt.Iface, tallies bytes per remote peer, and calls cb with
// the current ranking every opt.Interval until ctx is cancelled.
func TopTalkers(ctx context.Context, opt Options, cb func([]Talker)) error {
	handle, err := openCapture(opt.Iface)
	if err != nil {
		return err
	}
	defer handle.Close()

	interval := opt.Interval
	if interval <= 0 {
		interval = time.Second
	}

	acc := newAccumulator()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cb(acc.top(opt.Top, opt.Resolve, time.Second))
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			observePacket(acc, pkt)
		}
	}
}

// openCapture opens iface (or the first usable device if empty) for live
// capture. Shared by TopTalkers and TopProcesses.
func openCapture(iface string) (*pcap.Handle, error) {
	if iface == "" {
		var err error
		if iface, err = firstUsableDevice(); err != nil {
			return nil, err
		}
	}
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, ErrUnavailable
	}
	return handle, nil
}

// observePacket decodes one frame's network/link addresses and credits the
// accumulator with its length.
func observePacket(acc *accumulator, pkt gopacket.Packet) {
	var srcIP, dstIP, srcMAC, dstMAC string

	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		e := eth.(*layers.Ethernet)
		srcMAC, dstMAC = e.SrcMAC.String(), e.DstMAC.String()
	}
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
	acc.observe(srcIP, srcMAC, dstIP, dstMAC, length)
}

// pcapIfLoopback mirrors libpcap's PCAP_IF_LOOPBACK bit (pcap/pcap.h) — not
// exported as a named constant by gopacket's pcap package.
const pcapIfLoopback = 0x00000001

// firstUsableDevice picks the first device that has an address and is not
// loopback, as a sensible capture default.
func firstUsableDevice() (string, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range ifs {
		if len(d.Addresses) == 0 {
			continue
		}
		if d.Flags&pcapIfLoopback != 0 {
			continue
		}
		return d.Name, nil
	}
	return "", ErrUnavailable
}
