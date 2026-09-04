# Per-app traffic monitor — design

Status: approved by user 2026-09-04.

## Purpose

Show, live, which running applications/processes are using network
bandwidth on this machine, at what rate, and how much traffic cannot
be attributed to any known process ("system/background" bucket).
Extends the existing "who's using my network" family of features
(`bwmon` = per-NIC, `capture.TopTalkers` = per-remote-peer) with a
per-local-process view.

## Constraints established during brainstorming

- Real per-process byte/sec counts require packet capture. Windows has
  no free-standing perf counter for per-process network I/O; the only
  no-admin API (`GetPerTcpConnectionEStats`) only works for
  connections whose ESTATS collection was enabled at creation time by
  the *capturing* process, so it cannot retroactively instrument
  connections opened by other processes. The project already has a
  packet-capture backend (`internal/capture`, gopacket + Npcap/libpcap,
  behind `-tags pcap`) — this feature builds on it rather than adding
  a second capture path.
- Port→PID attribution: **Windows only** for now (via `iphlpapi.dll`,
  no admin required). Linux/macOS: `ErrUnavailable`.
- `gopacket` is not in `go.mod`/`go.sum` and this environment has no
  route to `proxy.golang.org`, so — same as the rest of
  `internal/capture` — the `-tags pcap` code path cannot be built or
  run here. The user builds and validates it locally with
  `go get github.com/google/gopacket && go build -tags pcap ./...`
  plus Npcap installed.

## Design

### `internal/capture` additions

Reuses the existing packet-capture loop and local-address detection;
adds process attribution alongside the existing remote-peer
attribution. No new package — this is the same "who's on my network"
capture, viewed by local process instead of remote IP.

```go
// ProcTraffic is one local process's (or the unattributed bucket's)
// observed traffic volume.
type ProcTraffic struct {
    PID     int    `json:"pid"`  // 0 = unattributed ("система/неизвестно")
    Name    string `json:"name"`
    RxMbps  float64 `json:"rx_mbps"`
    TxMbps  float64 `json:"tx_mbps"`
    Rx      uint64  `json:"rx_bytes"`
    Tx      uint64  `json:"tx_bytes"`
}

// TopProcesses opens opt.Iface, tallies bytes per local process
// (by port→PID attribution), and calls cb with the current ranking
// every opt.Interval until ctx is cancelled. Traffic that cannot be
// attributed to a known process (port reused, ICMP, short-lived
// connection) is reported under PID 0 ("Система/неизвестно").
func TopProcesses(ctx context.Context, opt Options, cb func([]ProcTraffic)) error
```

Implementation notes (`-tags pcap` build only):

- Reuses `pcap.OpenLive` / the same device-selection helper as
  `TopTalkers`.
- Decodes the TCP/UDP layer for src/dst port in addition to the
  existing IP layer decode. Direction: srcIP local → credit Tx to the
  process owning srcPort; dstIP local → credit Rx to the process
  owning dstPort.
- A new `processAccumulator` (parallel to the existing `accumulator`)
  tallies bytes by PID instead of by remote IP.
- Port→PID and PID→name are resolved through a package-level
  lookup, populated only on the Windows+pcap build
  (`pidlookup_windows_pcap.go`, `//go:build windows && pcap`):
  - `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`) and
    `GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`) via `iphlpapi.dll`,
    refreshed on a ~2s timer (not per-packet — connection tables
    churn slower than packets arrive).
  - Process name via `CreateToolhelp32Snapshot`
    (`TH32CS_SNAPPROCESS`), cached alongside the port map.
  - No admin rights required for either call.
- On any other OS (even built with `-tags pcap`), the lookup is
  unset and `TopProcesses` returns `ErrUnavailable` immediately,
  same as `!pcap` stub build (`capture_stub.go` gets a matching
  `TopProcesses` stub).
- A lookup miss (port already reused, process exited between capture
  and lookup, non-TCP/UDP traffic) is not an error — it is credited
  to PID 0, name "Система/неизвестно". This bucket is the direct
  answer to "how much does my background/system take."

### TUI: new "Приложения" tab

`internal/tui/tab_apps.go`, modeled on `tab_bw.go`:

- Table columns: PID, Имя процесса, Приём, Передача, Всего.
- Sorted descending by total (Rx+Tx) Mbps, refreshed once per
  second, same start/stop-on-Enter interaction as the Трафик tab.
- The "Система/неизвестно" row is included in the same table (not a
  separate widget) so it sorts naturally among the other rows.
- No sparkline chart in this iteration (unlike `tab_bw`) — a table is
  enough to answer "which app, how much"; can be added later if
  wanted.
- Registered in `internal/tui/app.go`'s tab list next to `newBWTab()`.
- If `capture.Available()` is false (default, non-pcap build) or the
  OS isn't Windows, the tab shows the same explanatory message pattern
  the LAN/discover tabs use for `ErrUnavailable`, telling the user how
  to enable it (`-tags pcap` + Npcap), rather than crashing or hiding
  the tab.

### Testing

- `internal/capture`: unit tests for `processAccumulator` (direction
  attribution, PID-0 fallback) using a fake/injectable PID lookup —
  no real pcap/syscalls needed, same style as `capture_test.go`'s
  existing accumulator tests.
- `pidlookup_windows_pcap.go` itself is untestable here (no Windows+
  pcap build in this environment); it's a thin wrapper over two
  Win32 calls and gets a doc comment noting it must be validated on
  a real Windows machine with Npcap installed, same caveat already
  attached to the rest of `-tags pcap` code.
- `internal/tui`: smoke test for the new tab following the existing
  `discover_smoke_test.go` pattern (renders without a live capture
  backend).

## Out of scope (this iteration)

- macOS/Linux port→PID attribution.
- Historical/export logging for per-app traffic (existing `history`
  tab mechanism could be wired in later if wanted).
- Sparkline chart per process.
- ESTATS-based no-pcap approximate mode.
