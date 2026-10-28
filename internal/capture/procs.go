// Per-process traffic accounting: groups the same captured bytes TopTalkers
// groups by remote peer, but by local process instead, so a viewer can see
// which application on this machine is using the bandwidth.
package capture

import (
	"fmt"
	"sort"
)

// ProcTraffic is one local process's (or the unattributed bucket's) traffic
// volume over the most recent sampling window.
type ProcTraffic struct {
	PID    int     `json:"pid"` // 0 = unattributed (see unattributedName)
	Name   string  `json:"name"`
	RxMbps float64 `json:"rx_mbps"`
	TxMbps float64 `json:"tx_mbps"`
	Rx     uint64  `json:"rx_bytes"`
	Tx     uint64  `json:"tx_bytes"`
}

// unattributedName is the display name for traffic that could not be matched
// to a local process: port already reused, connection gone by the time of
// lookup, or a non-TCP/UDP frame with no port to attribute by.
const unattributedName = "Система/неизвестно"

// processAccumulator tallies bytes per local process over one sampling
// window. lookup and name may be nil (no attribution backend available), in
// which case every byte lands in the PID-0 unattributed bucket.
type processAccumulator struct {
	local  map[string]bool
	byPID  map[int]*ProcTraffic
	lookup func(proto string, port uint16) (pid int, ok bool)
	name   func(pid int) string
}

func newProcessAccumulator(
	local map[string]bool,
	lookup func(proto string, port uint16) (int, bool),
	name func(int) string,
) *processAccumulator {
	return &processAccumulator{local: local, byPID: map[int]*ProcTraffic{}, lookup: lookup, name: name}
}

// observe credits one TCP/UDP frame to the local process that owns the
// local-side port: srcIP local -> outbound (Tx) credited by srcPort; dstIP
// local -> inbound (Rx) credited by dstPort. A frame where both or neither
// endpoint is local (loopback, or a peer-to-peer frame seen while
// promiscuous) is dropped — it isn't this host's traffic to attribute.
func (a *processAccumulator) observe(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16, length int) {
	srcLocal, dstLocal := a.local[srcIP], a.local[dstIP]
	switch {
	case srcLocal && !dstLocal:
		a.credit(proto, srcPort, length, true)
	case dstLocal && !srcLocal:
		a.credit(proto, dstPort, length, false)
	}
}

// observeOther credits a non-TCP/UDP frame (ICMP, etc.) straight to the
// unattributed bucket — it carries no port to attribute by.
func (a *processAccumulator) observeOther(srcIP, dstIP string, length int) {
	srcLocal, dstLocal := a.local[srcIP], a.local[dstIP]
	switch {
	case srcLocal && !dstLocal:
		a.creditPID(0, length, true)
	case dstLocal && !srcLocal:
		a.creditPID(0, length, false)
	}
}

func (a *processAccumulator) credit(proto string, localPort uint16, length int, isTx bool) {
	pid := 0
	if a.lookup != nil {
		if p, ok := a.lookup(proto, localPort); ok {
			pid = p
		}
	}
	a.creditPID(pid, length, isTx)
}

func (a *processAccumulator) creditPID(pid int, length int, isTx bool) {
	t := a.byPID[pid]
	if t == nil {
		t = &ProcTraffic{PID: pid, Name: a.displayName(pid)}
		a.byPID[pid] = t
	}
	if isTx {
		t.Tx += uint64(length)
	} else {
		t.Rx += uint64(length)
	}
}

func (a *processAccumulator) displayName(pid int) string {
	if pid == 0 {
		return unattributedName
	}
	if a.name != nil {
		if n := a.name(pid); n != "" {
			return n
		}
	}
	return fmt.Sprintf("PID %d", pid)
}

// rates converts the accumulated window into a ranked snapshot: RxMbps/TxMbps
// computed against secs, sorted by total traffic descending (PID ascending
// to break ties), truncated to n (0 = unlimited).
func (a *processAccumulator) rates(n int, secs float64) []ProcTraffic {
	list := make([]ProcTraffic, 0, len(a.byPID))
	for _, t := range a.byPID {
		r := *t
		if secs > 0 {
			r.RxMbps = bytesToMbps(r.Rx, secs)
			r.TxMbps = bytesToMbps(r.Tx, secs)
		}
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		ti, tj := list[i].Rx+list[i].Tx, list[j].Rx+list[j].Tx
		if ti != tj {
			return ti > tj
		}
		return list[i].PID < list[j].PID
	})
	if n > 0 && len(list) > n {
		list = list[:n]
	}
	return list
}

func bytesToMbps(deltaBytes uint64, secs float64) float64 {
	if secs <= 0 {
		return 0
	}
	return float64(deltaBytes) * 8 / secs / 1e6
}
