# Per-App Traffic Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a live "which app is using how much bandwidth" view: a per-process traffic accounting engine in `internal/capture`, plus a new "Приложения" TUI tab that shows it, with unattributed traffic (background/system) surfaced as its own row.

**Architecture:** Extends the existing `internal/capture` package (packet-capture-backed "who's on my network" feature) with a second accumulator that groups bytes by local process instead of by remote peer. Port→PID attribution is a pluggable package-level function, populated only on the Windows+`-tags pcap` build via `iphlpapi.dll`; everywhere else it stays nil and the feature reports `ErrUnavailable`, same as the rest of the package.

**Tech Stack:** Go 1.26, existing deps only (`gopacket`/`pcap` behind `-tags pcap`, `github.com/charmbracelet/bubbles/table`, `bubbletea`, `lipgloss`). No new dependencies. Windows: raw `syscall` calls into `iphlpapi.dll` and `kernel32.dll` (no `golang.org/x/sys` — keeps the dependency surface exactly what it is today).

**Spec:** `docs/superpowers/specs/2026-09-04-per-app-traffic-monitor-design.md`

## Global Constraints

- No new Go module dependencies beyond the already-accepted, already-optional `gopacket` (behind `-tags pcap`). Windows syscalls use the standard library `syscall` package directly.
- Port→PID attribution: **Windows only**, IPv4 (`AF_INET`) only. IPv6 connections and any lookup miss fall into the PID-0 "Система/неизвестно" bucket — this is a designed fallback, not an error path.
- Code behind `-tags pcap` (and `windows && pcap`) cannot be built or run in this development environment (no route to `proxy.golang.org` to fetch `gopacket`, and this box may not be the target Windows+Npcap machine at build time). Every task touching those files says explicitly how it was checked instead of `go test` (gofmt syntax check + manual review), and the plan's last task tells the user how to validate for real.
- All user-facing strings are Russian, matching the rest of the TUI/CLI (see existing `internal/capture/cli.go`, `internal/tui/tab_bw.go`).
- Follow existing code style: no doc-comment paragraphs beyond a one-line purpose statement per exported symbol, matching `internal/capture/capture.go` and `internal/bwmon/bwmon.go`.

---

## Task 1: `ProcTraffic` type and `processAccumulator`

**Files:**
- Create: `internal/capture/procs.go`
- Test: `internal/capture/procs_test.go`

**Interfaces:**
- Produces: `type ProcTraffic struct{ PID int; Name string; RxMbps, TxMbps float64; Rx, Tx uint64 }` (JSON tags: `pid`, `name`, `rx_mbps`, `tx_mbps`, `rx_bytes`, `tx_bytes`), `const unattributedName = "Система/неизвестно"`, `newProcessAccumulator(local map[string]bool, lookup func(proto string, port uint16) (int, bool), name func(int) string) *processAccumulator`, `(*processAccumulator).observe(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16, length int)`, `(*processAccumulator).observeOther(srcIP, dstIP string, length int)`, `(*processAccumulator).rates(n int, secs float64) []ProcTraffic`.
- Consumes: nothing from other tasks (this is the foundation both `procs_pcap.go` (Task 3) and `tab_apps.go` (Task 5) build on).

- [ ] **Step 1: Write the failing tests**

Create `internal/capture/procs_test.go`:

```go
package capture

import "testing"

func newTestProcAcc(lookup func(string, uint16) (int, bool), name func(int) string, local ...string) *processAccumulator {
	set := map[string]bool{}
	for _, ip := range local {
		set[ip] = true
	}
	return newProcessAccumulator(set, lookup, name)
}

func TestProcessAccumulatorAttributesByLocalPort(t *testing.T) {
	lookup := func(proto string, port uint16) (int, bool) {
		if proto == "tcp" && port == 51000 {
			return 4242, true
		}
		return 0, false
	}
	names := func(pid int) string {
		if pid == 4242 {
			return "chrome.exe"
		}
		return ""
	}
	acc := newTestProcAcc(lookup, names, "192.168.1.10")

	// Outbound: local port 51000 -> remote 443 (upload).
	acc.observe("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, 1000)
	// Inbound: remote 443 -> local port 51000 (download).
	acc.observe("tcp", "8.8.8.8", 443, "192.168.1.10", 51000, 3000)

	got := acc.rates(0, 1)
	if len(got) != 1 {
		t.Fatalf("got %d processes, want 1: %+v", len(got), got)
	}
	if got[0].PID != 4242 || got[0].Name != "chrome.exe" {
		t.Errorf("process = %+v, want PID 4242/chrome.exe", got[0])
	}
	if got[0].Tx != 1000 || got[0].Rx != 3000 {
		t.Errorf("Tx/Rx = %d/%d, want 1000/3000", got[0].Tx, got[0].Rx)
	}
}

func TestProcessAccumulatorUnattributedFallsBackToSystemBucket(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observe("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, 500)

	got := acc.rates(0, 1)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].PID != 0 || got[0].Name != unattributedName {
		t.Errorf("got %+v, want PID 0 / %q", got[0], unattributedName)
	}
}

func TestProcessAccumulatorObserveOtherGoesToSystemBucket(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observeOther("192.168.1.10", "8.8.8.8", 64) // e.g. ICMP echo request

	got := acc.rates(0, 1)
	if len(got) != 1 || got[0].PID != 0 || got[0].Tx != 64 {
		t.Errorf("got %+v, want single PID-0 row with Tx=64", got)
	}
}

func TestProcessAccumulatorDropsLoopbackAndNonLocalFrames(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "192.168.1.10")
	acc.observe("tcp", "127.0.0.1", 1, "127.0.0.1", 2, 100) // both local
	acc.observe("tcp", "8.8.8.8", 1, "1.1.1.1", 2, 100)     // neither local
	if got := acc.rates(0, 1); len(got) != 0 {
		t.Errorf("expected no rows, got %+v", got)
	}
}

func TestProcessAccumulatorRatesSortedByTotalDescending(t *testing.T) {
	lookup := func(proto string, port uint16) (int, bool) { return int(port), true }
	acc := newTestProcAcc(lookup, nil, "10.0.0.1")
	acc.observe("tcp", "10.0.0.1", 100, "1.1.1.1", 1, 500)  // pid 100, total 500
	acc.observe("tcp", "10.0.0.1", 200, "1.1.1.1", 1, 1500) // pid 200, total 1500

	got := acc.rates(0, 1)
	if len(got) != 2 || got[0].PID != 200 || got[1].PID != 100 {
		t.Errorf("wrong order: %+v", got)
	}
	if got[0].Name != "PID 200" {
		t.Errorf("fallback name = %q, want %q", got[0].Name, "PID 200")
	}
}

func TestProcessAccumulatorRatesComputesMbps(t *testing.T) {
	acc := newTestProcAcc(nil, nil, "10.0.0.1")
	acc.observe("tcp", "1.1.1.1", 1, "10.0.0.1", 100, 1_000_000) // 1MB inbound
	got := acc.rates(0, 1)                                       // over 1 second
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	want := 8.0 // 1,000,000 bytes * 8 / 1s / 1e6 = 8 Mbps
	if got[0].RxMbps < want-0.01 || got[0].RxMbps > want+0.01 {
		t.Errorf("RxMbps = %f, want ~%f", got[0].RxMbps, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/capture/... -run TestProcessAccumulator -v`
Expected: FAIL — `undefined: newProcessAccumulator` (and friends); `procs.go` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/capture/procs.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/capture/... -run TestProcessAccumulator -v`
Expected: PASS (all 6 tests).

- [ ] **Step 5: Run the full existing capture test suite to check for regressions**

Run: `go test ./internal/capture/...`
Expected: PASS (existing `TestAccumulator*`, `TestIsRemoteUnicast`, `TestStubUnavailable` unaffected — `procs.go` only adds new symbols).

- [ ] **Step 6: Commit**

```bash
git add internal/capture/procs.go internal/capture/procs_test.go
git commit -m "$(cat <<'EOF'
feat(capture): add per-process traffic accumulator

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HrqaJj8buohw1UMWwssCpH
EOF
)"
```

---

## Task 2: `TopProcesses` stub for the default (`!pcap`) build

**Files:**
- Modify: `internal/capture/capture_stub.go`
- Test: `internal/capture/procs_test.go` (append)

**Interfaces:**
- Consumes: `ProcTraffic` (Task 1), `Options` (existing, `capture.go`), `ErrUnavailable` (existing, `capture.go`).
- Produces: `func TopProcesses(ctx context.Context, opt Options, cb func([]ProcTraffic)) error` — the symbol `tab_apps.go` (Task 5) and the real pcap implementation (Task 3) both key off. Must exist identically (same signature) in both the `!pcap` and `pcap` builds so callers don't need a build tag of their own.

- [ ] **Step 1: Write the failing test**

Append to `internal/capture/procs_test.go`:

```go
func TestStubTopProcessesUnavailable(t *testing.T) {
	if Available() {
		t.Skip("pcap build; stub test not applicable")
	}
	err := TopProcesses(context.Background(), Options{}, func([]ProcTraffic) {})
	if err != ErrUnavailable {
		t.Errorf("TopProcesses err = %v, want ErrUnavailable", err)
	}
}
```

Add `"context"` to the file's import block (now `import ("context"; "testing")`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/capture/... -run TestStubTopProcessesUnavailable -v`
Expected: FAIL — `undefined: TopProcesses`.

- [ ] **Step 3: Implement the stub**

Modify `internal/capture/capture_stub.go` — add after the existing `TopTalkers` stub:

```go
// TopProcesses streams per-process traffic. Unavailable without -tags pcap.
func TopProcesses(ctx context.Context, opt Options, cb func([]ProcTraffic)) error {
	return ErrUnavailable
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/capture/... -run TestStubTopProcessesUnavailable -v`
Expected: PASS.

- [ ] **Step 5: Run the full package test suite**

Run: `go test ./internal/capture/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/capture/capture_stub.go internal/capture/procs_test.go
git commit -m "$(cat <<'EOF'
feat(capture): stub TopProcesses for the default (non-pcap) build

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HrqaJj8buohw1UMWwssCpH
EOF
)"
```

---

## Task 3: Real `TopProcesses` for the `-tags pcap` build

**Files:**
- Modify: `internal/capture/capture_pcap.go` (extract a shared `openCapture` helper)
- Create: `internal/capture/procs_pcap.go` (`//go:build pcap`)

**Interfaces:**
- Consumes: `processAccumulator`, `ProcTraffic` (Task 1); `localIPSet()`, `ErrUnavailable`, `Options`, `firstUsableDevice()` (existing, `capture.go`/`capture_pcap.go`).
- Produces: `var pidLookup func(proto string, port uint16) (pid int, ok bool)` and `var procName func(pid int) string` — package-level hooks that Task 4's Windows file sets via `init()`. Real `TopProcesses(ctx, opt, cb) error`, matching the Task 2 stub's signature exactly.

**Not testable in this environment:** this file requires `-tags pcap` and `gopacket`, which cannot be fetched here (no route to `proxy.golang.org`) or built without a pcap runtime installed. Verification here is `gofmt -l` (syntax only) plus careful manual review against the existing, already-accepted `capture_pcap.go` pattern. The user validates for real per Task 5's closing note.

- [ ] **Step 1: Extract a shared `openCapture` helper in `capture_pcap.go`**

In `internal/capture/capture_pcap.go`, replace the device-selection + `pcap.OpenLive` lines inside `TopTalkers` with a call to a new helper, so `TopProcesses` can reuse the exact same logic instead of duplicating it.

Change:

```go
func TopTalkers(ctx context.Context, opt Options, cb func([]Talker)) error {
	iface := opt.Iface
	if iface == "" {
		var err error
		if iface, err = firstUsableDevice(); err != nil {
			return err
		}
	}
	interval := opt.Interval
	if interval <= 0 {
		interval = time.Second
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return ErrUnavailable
	}
	defer handle.Close()
```

to:

```go
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
```

Add the new helper (e.g. right after `TopTalkers`, before `observePacket`):

```go
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
```

- [ ] **Step 2: Syntax-check the edit**

Run: `gofmt -l internal/capture/capture_pcap.go`
Expected: no output (file is syntactically valid and already formatted). This cannot be `go build`-verified here since it needs `-tags pcap` and an unfetchable dependency; gofmt is the closest available check.

- [ ] **Step 3: Create `internal/capture/procs_pcap.go`**

```go
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
```

- [ ] **Step 4: Syntax-check the new file**

Run: `gofmt -l internal/capture/procs_pcap.go`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add internal/capture/capture_pcap.go internal/capture/procs_pcap.go
git commit -m "$(cat <<'EOF'
feat(capture): add TopProcesses for the pcap build

Shares the openCapture device-open path with TopTalkers. Port->PID
attribution is a pluggable hook (nil by default, wired up per-platform);
unattributed traffic reports under the PID-0 bucket rather than being
dropped. Untested in this environment (-tags pcap, unfetchable gopacket) —
gofmt-checked only; see Task 5's validation note.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HrqaJj8buohw1UMWwssCpH
EOF
)"
```

---

## Task 4: Windows port→PID and PID→name attribution backend

**Files:**
- Create: `internal/capture/pidlookup_windows_pcap.go` (`//go:build windows && pcap`)

**Interfaces:**
- Consumes: the `pidLookup`/`procName` package vars declared in Task 3's `procs_pcap.go`.
- Produces: sets `pidLookup = windowsPortPID` and `procName = windowsProcessName` via `init()` — no new exported API; `TopProcesses` picks these up automatically once this file is in the build.

**Not testable in this environment:** Windows syscalls into `iphlpapi.dll`/`kernel32.dll`, gated behind `windows && pcap`. Verification here is `gofmt -l` plus manual review of the struct layouts against the documented Win32 `MIB_TCPROW_OWNER_PID`/`MIB_UDPROW_OWNER_PID`/`PROCESSENTRY32W` shapes. Real validation happens on a Windows machine with Npcap (see Task 5's closing note).

- [ ] **Step 1: Create `internal/capture/pidlookup_windows_pcap.go`**

```go
//go:build windows && pcap

// Windows port->PID and PID->process-name attribution for TopProcesses, via
// iphlpapi.dll (GetExtendedTcpTable/GetExtendedUdpTable) and
// CreateToolhelp32Snapshot. Neither call requires administrator rights.
//
// Scope: IPv4 (AF_INET) connections only. IPv6 rows use a different, larger
// MIB_TCP6ROW_OWNER_PID/MIB_UDP6ROW_OWNER_PID layout (16-byte address + scope
// id) not implemented here — IPv6 traffic simply falls through to the
// unattributed "Система/неизвестно" bucket, same as any other lookup miss.
package capture

import (
	"encoding/binary"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	afInet              = 2
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	th32csSnapProcess   = 0x00000002
	maxPath             = 260
)

var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetExtendedTCPTable  = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable  = modIphlpapi.NewProc("GetExtendedUdpTable")
	procCreateToolhelp32Snap = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW       = modKernel32.NewProc("Process32NextW")
	procCloseHandle          = modKernel32.NewProc("CloseHandle")
)

// mibTCPRowOwnerPID mirrors Win32's MIB_TCPROW_OWNER_PID (six DWORDs).
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// mibUDPRowOwnerPID mirrors Win32's MIB_UDPROW_OWNER_PID (three DWORDs).
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// processEntry32W mirrors Win32's PROCESSENTRY32W.
type processEntry32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

type portKey struct {
	proto string
	port  uint16
}

const pidMapTTL = 2 * time.Second

var (
	pidMapMu sync.Mutex
	pidMap   = map[portKey]int{}
	nameMap  = map[int]string{}
	pidMapAt time.Time
)

func init() {
	pidLookup = windowsPortPID
	procName = windowsProcessName
}

// windowsPortPID is TopProcesses' pidLookup hook: the PID owning localPort
// for proto ("tcp"/"udp"), refreshing the underlying snapshot at most once
// every pidMapTTL.
func windowsPortPID(proto string, port uint16) (int, bool) {
	pidMapMu.Lock()
	defer pidMapMu.Unlock()
	if time.Since(pidMapAt) > pidMapTTL {
		refreshLocked()
	}
	pid, ok := pidMap[portKey{proto, port}]
	return pid, ok
}

// windowsProcessName is TopProcesses' procName hook, reading the same cached
// snapshot windowsPortPID refreshes.
func windowsProcessName(pid int) string {
	pidMapMu.Lock()
	defer pidMapMu.Unlock()
	if time.Since(pidMapAt) > pidMapTTL {
		refreshLocked()
	}
	return nameMap[pid]
}

// refreshLocked rebuilds pidMap/nameMap. Caller must hold pidMapMu.
func refreshLocked() {
	m := make(map[portKey]int, len(pidMap))
	for _, row := range readTCPTable() {
		m[portKey{"tcp", ntohsPort(row.LocalPort)}] = int(row.OwningPid)
	}
	for _, row := range readUDPTable() {
		m[portKey{"udp", ntohsPort(row.LocalPort)}] = int(row.OwningPid)
	}
	pidMap = m
	nameMap = snapshotProcessNames()
	pidMapAt = time.Now()
}

// ntohsPort extracts the 16-bit port number from a MIB_*ROW_OWNER_PID's
// LocalPort field, which Windows stores in network (big-endian) byte order
// in the low word of the DWORD.
func ntohsPort(v uint32) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v), byte(v >> 8)})
}

// readTCPTable returns the current IPv4 TCP table via
// GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL). Returns nil on any failure —
// callers treat "no table" the same as "nothing known yet".
func readTCPTable() []mibTCPRowOwnerPID {
	var size uint32
	procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil
	}
	return parseTCPRows(buf)
}

func parseTCPRows(buf []byte) []mibTCPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	rows := make([]mibTCPRowOwnerPID, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		rows = append(rows, *(*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[off])))
	}
	return rows
}

// readUDPTable returns the current IPv4 UDP table via
// GetExtendedUdpTable(UDP_TABLE_OWNER_PID).
func readUDPTable() []mibUDPRowOwnerPID {
	var size uint32
	procGetExtendedUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPID, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUDPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPID, 0)
	if ret != 0 {
		return nil
	}
	return parseUDPRows(buf)
}

func parseUDPRows(buf []byte) []mibUDPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	const rowSize = int(unsafe.Sizeof(mibUDPRowOwnerPID{}))
	rows := make([]mibUDPRowOwnerPID, 0, n)
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		rows = append(rows, *(*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[off])))
	}
	return rows
}

// snapshotProcessNames returns every running PID's executable filename via
// CreateToolhelp32Snapshot — no administrator rights required.
func snapshotProcessNames() map[int]string {
	h, _, _ := procCreateToolhelp32Snap.Call(uintptr(th32csSnapProcess), 0)
	if h == 0 || h == ^uintptr(0) {
		return map[int]string{}
	}
	defer procCloseHandle.Call(h)

	out := map[int]string{}
	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		out[int(entry.ProcessID)] = syscall.UTF16ToString(entry.ExeFile[:])
		entry = processEntry32W{Size: uint32(unsafe.Sizeof(entry))}
		ret, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
	}
	return out
}
```

- [ ] **Step 2: Syntax-check the new file**

Run: `gofmt -l internal/capture/pidlookup_windows_pcap.go`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add internal/capture/pidlookup_windows_pcap.go
git commit -m "$(cat <<'EOF'
feat(capture): Windows port->PID attribution via iphlpapi

GetExtendedTcpTable/GetExtendedUdpTable for port->PID (IPv4 only,
no admin required), CreateToolhelp32Snapshot for PID->exe name.
Cached with a 2s TTL since the connection table churns slower than
packets arrive. Untested in this environment (windows && pcap,
no Windows+Npcap toolchain here) — gofmt-checked only.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HrqaJj8buohw1UMWwssCpH
EOF
)"
```

---

## Task 5: "Приложения" TUI tab

**Files:**
- Create: `internal/tui/tab_apps.go`
- Modify: `internal/tui/app.go`
- Test: `internal/tui/tab_apps_test.go`

**Interfaces:**
- Consumes: `capture.Available() bool`, `capture.TopProcesses(ctx, capture.Options, func([]capture.ProcTraffic)) error`, `capture.ProcTraffic` (Tasks 1-3); `newStyles()`, `styles`, `newTable()`, `trunc()`, `listen()`, `fmtMbps()` (existing `internal/tui` helpers, see `tab_bw.go`/`components.go`/`tab_discover.go`).
- Produces: `newAppsTab() tab`, `type appsTab struct{...}` implementing the `tab` interface — registered into `model.tabs` in `app.go`. Nothing else depends on this task.

- [ ] **Step 1: Write the failing tests**

Create `internal/tui/tab_apps_test.go`:

```go
package tui

import (
	"strings"
	"testing"

	"speedtest/internal/capture"
)

// TestAppsTabShowsUnavailableWithoutPcap checks the Приложения tab explains
// itself instead of offering a monitor that would just error, when built
// without -tags pcap (the default build, and the only one exercised here).
func TestAppsTabShowsUnavailableWithoutPcap(t *testing.T) {
	tab := newAppsTab()
	tab.SetSize(100, 24)
	out := tab.View()

	at, ok := tab.(*appsTab)
	if !ok {
		t.Fatalf("newAppsTab() = %T, want *appsTab", tab)
	}
	if at.running {
		t.Error("should not be running before Enter")
	}
	if !strings.Contains(out, "Приложения") {
		t.Errorf("frame title missing\n%s", out)
	}
	if !strings.Contains(out, "-tags pcap") {
		t.Errorf("expected pcap-unavailable explanation, got:\n%s", out)
	}
}

// TestAppsTabRefreshRowsFormatsUnattributedBucket checks the PID-0 "system"
// row renders with a dash instead of "0", alongside a normal process row.
func TestAppsTabRefreshRowsFormatsUnattributedBucket(t *testing.T) {
	at := newAppsTab().(*appsTab)
	at.SetSize(120, 24)
	at.procs = []capture.ProcTraffic{
		{PID: 4242, Name: "chrome.exe", RxMbps: 2.5, TxMbps: 0.5},
		{PID: 0, Name: "Система/неизвестно", RxMbps: 0.1, TxMbps: 0.0},
	}
	at.refreshRows()

	rows := at.tbl.Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0][0] != "4242" || rows[0][1] != "chrome.exe" {
		t.Errorf("row 0 = %+v, want PID 4242/chrome.exe", rows[0])
	}
	if rows[1][0] != "-" {
		t.Errorf("system row PID = %q, want %q", rows[1][0], "-")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/tui/... -run TestAppsTab -v`
Expected: FAIL — `undefined: newAppsTab` (`tab_apps.go` doesn't exist yet).

- [ ] **Step 3: Create `internal/tui/tab_apps.go`**

```go
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/capture"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type appRateMsg struct {
	procs []capture.ProcTraffic
	err   error
}

// appsTab shows live per-process network throughput: which application is
// using how much bandwidth right now, plus a "Система/неизвестно" bucket for
// traffic that couldn't be matched to a process.
type appsTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg

	cancel context.CancelFunc
	spin   spinner.Model
	tbl    table.Model

	running bool
	procs   []capture.ProcTraffic
	err     error
}

func newAppsTab() tab {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sty := newStyles()
	sp.Style = sty.accent
	return &appsTab{sty: sty, spin: sp, tbl: newTable(appsColumns(80), 10)}
}

func (t *appsTab) Title() string { return "Приложения" }
func (t *appsTab) Init() tea.Cmd { return nil }
func (t *appsTab) Busy() bool    { return t.running }

func (t *appsTab) ShortHelp() []string {
	if !capture.Available() {
		return nil
	}
	if t.running {
		return []string{"[Enter] стоп", "[↑/↓] прокрутка"}
	}
	return []string{"[Enter] старт мониторинга", "[↑/↓] прокрутка"}
}

func (t *appsTab) Capturing() bool { return false }

func (t *appsTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(appsColumns(w))
	t.tbl.SetHeight(max(h-6, 3))
}

func appsColumns(w int) []table.Column {
	const pidW, rxW, txW, totW = 8, 12, 12, 12
	nameW := max(w-pidW-rxW-txW-totW-10, 12)
	return []table.Column{
		{Title: "PID", Width: pidW},
		{Title: "Процесс", Width: nameW},
		{Title: "Приём", Width: rxW},
		{Title: "Передача", Width: txW},
		{Title: "Всего", Width: totW},
	}
}

func (t *appsTab) start() tea.Cmd {
	t.running = true
	t.err = nil
	t.procs = nil
	t.tbl.SetRows(nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 8)
	t.ch = ch
	go func() {
		err := capture.TopProcesses(ctx, capture.Options{Interval: time.Second}, func(p []capture.ProcTraffic) {
			ch <- appRateMsg{procs: p}
		})
		if err != nil && ctx.Err() == nil {
			ch <- appRateMsg{err: err}
		}
	}()
	return tea.Batch(listen(ch), t.spin.Tick)
}

func (t *appsTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
}

func (t *appsTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	if !capture.Available() {
		return t, nil
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if t.running {
				t.stop()
			} else {
				return t, t.start()
			}
			return t, nil
		}
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd

	case appRateMsg:
		if !t.running {
			return t, nil
		}
		if msg.err != nil {
			t.err = msg.err
			t.stop()
			return t, nil
		}
		t.procs = msg.procs
		t.refreshRows()
		return t, listen(t.ch)

	case spinner.TickMsg:
		if !t.running {
			return t, nil
		}
		var cmd tea.Cmd
		t.spin, cmd = t.spin.Update(msg)
		return t, cmd
	}
	return t, nil
}

func (t *appsTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.procs))
	for _, p := range t.procs {
		pid := fmt.Sprintf("%d", p.PID)
		if p.PID == 0 {
			pid = "-"
		}
		rows = append(rows, table.Row{
			pid,
			trunc(p.Name, 28),
			fmt.Sprintf("%.2f Мбит/с", p.RxMbps),
			fmt.Sprintf("%.2f Мбит/с", p.TxMbps),
			fmt.Sprintf("%.2f Мбит/с", p.RxMbps+p.TxMbps),
		})
	}
	t.tbl.SetRows(rows)
}

func (t *appsTab) View() string {
	var b strings.Builder

	if !capture.Available() {
		b.WriteString(t.sty.muted.Render(
			"Трафик по приложениям требует захвата пакетов.\n" +
				"Соберите с -tags pcap (нужен Npcap на Windows) — обычной сборкой недоступно."))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	if t.err != nil {
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	if !t.running && len(t.procs) == 0 {
		b.WriteString(t.sty.muted.Render(
			"Живой трафик по процессам этой машины (кто сколько качает).\n" +
				"Неопознанный трафик попадает в «Система/неизвестно». Нажмите Enter."))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	status := t.sty.muted.Render("остановлено")
	if t.running {
		status = t.sty.accent.Render(t.spin.View() + " идёт замер")
	}
	fmt.Fprintf(&b, "%s\n\n", status)
	b.WriteString(t.tbl.View())

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Приложения", t.w, t.h, b.String()))
}
```

- [ ] **Step 4: Register the tab in `internal/tui/app.go`**

In `internal/tui/app.go`, add `newAppsTab()` to the `tabs` slice in `New()`, right after `newBWTab()`:

```go
			newBWTab(),
			newAppsTab(),
			newHTTPDLTab(cfg.HTTPURL),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/tui/... -run TestAppsTab -v`
Expected: PASS (both tests).

- [ ] **Step 6: Run the full existing TUI test suite to check for regressions**

Run: `go test ./internal/tui/...`
Expected: PASS (adding a tab to the slice doesn't change existing tabs' indices-by-name lookups; if any existing test indexes `model.tabs` positionally, this step is where that would surface — fix by locating the new tab appropriately rather than reordering).

- [ ] **Step 7: Build the default (non-pcap) binary to confirm nothing else broke**

Run: `go build ./...`
Expected: succeeds. This is the one full-project check available in this environment (no `-tags pcap`), and it's the build most users run.

- [ ] **Step 8: Commit**

```bash
git add internal/tui/tab_apps.go internal/tui/tab_apps_test.go internal/tui/app.go
git commit -m "$(cat <<'EOF'
feat(tui): add Приложения tab for per-process traffic

Shows live Rx/Tx by process (from capture.TopProcesses), with an
explanatory message instead of a crash when built without -tags pcap.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HrqaJj8buohw1UMWwssCpH
EOF
)"
```

- [ ] **Step 9: Note for manual validation on Windows**

None of Tasks 3-4's pcap/Windows code has run anywhere yet. Before considering the feature done, build and check it for real:

```bash
go get github.com/google/gopacket
go build -tags pcap ./...
```

Install Npcap (with "WinPcap API-compatible mode" during setup) if not already present, then run the built binary, open the "Приложения" tab, press Enter, and confirm: known processes (a browser tab downloading something, a background updater) show up by name with plausible Rx/Tx; the "Система/неизвестно" row stays small relative to attributed traffic under normal conditions.

---

## Self-Review

**Spec coverage:**
- `ProcTraffic` type, port→PID attribution (Windows, IPv4, iphlpapi, no admin) → Task 1 (type) + Task 4 (backend). ✓
- `TopProcesses` reusing the capture loop, PID-0 fallback bucket → Task 3. ✓
- Default/`!windows` build returns `ErrUnavailable` → Task 2 (stub) + Task 3's `pidLookup == nil` guard. ✓
- New "Приложения" TUI tab, table of PID/name/Rx/Tx/total, sorted descending, unavailable-message pattern → Task 5. ✓
- Testing: `processAccumulator` unit tests with injectable lookup → Task 1. `pidlookup_windows_pcap.go` flagged untestable here, validated manually → Task 4 + Task 5 Step 9. TUI smoke test → Task 5. ✓
- Out-of-scope items (macOS/Linux attribution, history/export, sparkline, ESTATS mode) — correctly not tasked. ✓

**Placeholder scan:** no TBD/TODO; every step has real code or a real shell command. ✓

**Type consistency:** `TopProcesses(ctx context.Context, opt Options, cb func([]ProcTraffic)) error` is identical across the Task 2 stub and Task 3 real implementation. `pidLookup func(proto string, port uint16) (pid int, ok bool)` / `procName func(pid int) string` match between their declaration (Task 3) and their assignment (Task 4). `processAccumulator`'s constructor and method signatures match between Task 1's definition and Task 3's call site. `appsTab.procs []capture.ProcTraffic` and `refreshRows()` match between Task 5's implementation and its test. ✓
