# Network Toolkit Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six new headless subcommands (wol, tls, timing, info, dns, bloat) and three new TUI tabs (DNS, Инфо, TLS) to the `speedtest` CLI, each its own commit with build/vet/test/fmt gates.

**Architecture:** Each command gets its own `internal/<pkg>` package exposing a pure/testable core plus a `Run<X>(args []string) error` CLI entry point, following the existing pattern in `internal/ping`, `internal/webspeed`. main.go's usage string and switch get one new case per command. TUI tabs follow the `tab_httpdl.go` pattern (simplest existing tab) and get registered in `internal/tui/app.go`'s `New()`.

**Tech Stack:** Go stdlib (`net`, `crypto/tls`, `net/http/httptrace`, `encoding/json`, `flag`), existing `speedtest/internal/util` helpers, existing Bubble Tea/Lip Gloss TUI stack. No new dependencies.

**Spec:** user-provided Russian task description (not a separate file) — summarized per task below.

## Global Constraints

- All user-facing CLI/TUI output in Russian, matching existing commands' tone.
- `--json` flag where the command has a clean result struct to marshal.
- Unit tests only for pure logic (parsing, formatting, grading) — no tests that require real network access.
- Run `go build ./... && go vet ./... && go test ./...` and `gofmt -l .` before every commit; fix before committing.
- Do not modify `internal/portscan/ports.go`, `internal/portscan/scan.go`, `internal/portscan/banner.go` (uncommitted work already in the tree, out of scope).
- One command/feature per commit, in the order listed below.

## Review Focus

- `wol`: a MAC with separators other than `:`/`-` (e.g. no separator, or uppercase) should still parse; reject wrong-length input with a clear Russian error instead of a panic.
- `tls`: a host with no port must default to 443; an expired or self-signed cert must still display (don't hard-fail on verification error — report it as a field).
- `timing`: an HTTPS URL vs HTTP URL — TLS stage must show 0/absent for plain HTTP, not a bogus value.
- `dns`: a server or domain that fails to resolve must not abort the whole table — show it as a failed row/cell.
- `bloat`: grading thresholds must be deterministic and unit-tested without touching the network (pure function from latency-increase-ms to grade).

---

## Task 1: `speedtest wol <mac>` — Wake-on-LAN

**Files:**
- Create: `internal/wol/wol.go`
- Create: `internal/wol/wol_test.go`
- Modify: `main.go` (usage string + switch case)

**Interfaces:**
- Produces: `wol.RunWOL(args []string) error`, `wol.BuildPacket(mac string) ([]byte, error)`, `wol.ParseMAC(s string) ([6]byte, error)`

Logic: parse MAC allowing `:`, `-`, or no separator (12 hex chars); build 102-byte magic packet (6×`0xFF` + 16×MAC); send via `net.DialUDP("udp4", nil, resolvedAddr)` to `--ip` (default `255.255.255.255`) and `--port` (default `9`) and `.Write` the packet — confirmed empirically that Go's UDP socket allows broadcast writes without extra setsockopt plumbing. Flags: `--ip`, `--port`. Positional: mac. Print Russian confirmation with target MAC/IP/port.

Tests: `ParseMAC` table test (colon, dash, bare-hex, uppercase, wrong length, bad hex char) and `BuildPacket` byte-layout test (length 102, first 6 bytes `0xFF`, remaining is MAC repeated 16×).

- [x] Write wol.go + wol_test.go, wire main.go, run gates, commit.

## Task 2: `speedtest tls <host[:port]>` — TLS certificate inspection

**Files:**
- Create: `internal/tlsinfo/tlsinfo.go`
- Create: `internal/tlsinfo/tlsinfo_test.go`
- Modify: `main.go`

**Interfaces:**
- Produces: `tlsinfo.RunTLS(args []string) error`, `tlsinfo.Inspect(hostport string, timeout time.Duration) (tlsinfo.Result, error)`, `tlsinfo.Result{Host, Issuer, Subject, NotBefore, NotAfter, Version string, CipherSuite string, SANs []string, HandshakeMs float64, VerifyError string}`

Logic: default port 443 if missing (reuse `ping.NormalizeHost` or local equivalent); `tls.Dial("tcp", hostport, &tls.Config{InsecureSkipVerify: true})`, time the dial as handshake duration; read `conn.ConnectionState()` for `PeerCertificates[0]`, `Version` (map via `tls.VersionName` if available in Go stdlib, else local switch), `CipherSuiteName`. Separately run `cert.Verify(...)` or just `conn.ConnectionState()` — if the original dial's `VerifiedChains` is empty despite `InsecureSkipVerify`, note that verification was skipped; capture any verify error by doing a second dial with `InsecureSkipVerify:false` only to capture the error string (best-effort, ignore dial error from that second attempt besides extracting the message).

Tests: pure formatting helpers only (e.g. a `tlsVersionName(uint16) string` table test, SAN-join formatting) — no real `tls.Dial` in tests.

- [x] Write tlsinfo.go + tlsinfo_test.go, wire main.go, run gates, commit.

## Task 3: `speedtest timing <url>` — HTTP request timing breakdown

**Files:**
- Create: `internal/timing/timing.go`
- Create: `internal/timing/timing_test.go`
- Modify: `main.go`

**Interfaces:**
- Produces: `timing.RunTiming(args []string) error`, `timing.Measure(url string, timeout time.Duration) (timing.Result, error)`, `timing.Result{URL string, DNSMs, ConnectMs, TLSMs, TTFBMs, TotalMs float64, StatusCode int}`

Logic: build `httptrace.ClientTrace` with `DNSStart/DNSDone`, `ConnectStart/ConnectDone`, `TLSHandshakeStart/TLSHandshakeDone`, `GotFirstResponseByte`; wrap request context via `httptrace.WithClientTrace`; record `time.Now()` deltas between hook pairs; `TLSMs` stays `0` when the trace never calls `TLSHandshakeStart` (plain HTTP). `TotalMs` = time from request start to `GotFirstResponseByte` (download-to-EOF not included, matches "итог" = time-to-first-byte pipeline, document in comment that body isn't drained for timing purposes but must still be closed/discarded).

Tests: a pure "format stage line" helper test (given a `Result`, output deterministic Russian strings) — no real HTTP call in tests.

- [x] Write timing.go + timing_test.go, wire main.go, run gates, commit.

## Task 4: `speedtest info` — local + external network info

**Files:**
- Create: `internal/netinfo/netinfo.go`
- Create: `internal/netinfo/netinfo_unix.go` (gateway/DNS via `/proc/net/route` + `/etc/resolv.conf`, build tag `linux`)
- Create: `internal/netinfo/netinfo_other.go` (best-effort fallback for other OSes, build tag `!linux`)
- Create: `internal/netinfo/netinfo_test.go`
- Modify: `main.go`

**Interfaces:**
- Produces: `netinfo.RunInfo(args []string) error`, `netinfo.Gather(ctx) (netinfo.Result, error)`, `netinfo.Result{ExternalIP, ISP, City, Country string, Interfaces []netinfo.IfaceInfo, Gateway string, DNSServers []string, IPv6 bool}`, `netinfo.IfaceInfo{Name, MAC string, IPs []string}`
- Platform hook: `defaultGateway() (string, error)` and `systemDNS() ([]string, error)` implemented per-OS file.

Logic: external IP/ISP via `GET http://ip-api.com/json/` (stdlib `net/http`, short timeout, decode JSON fields `query`, `isp`, `city`, `country`); local interfaces via `net.Interfaces()` + `.Addrs()`, skip loopback/down; gateway by parsing `/proc/net/route` (linux) for the default route (`Destination == 00000000`), hex-decode the gateway field (little-endian) into dotted IP; DNS servers by parsing `/etc/resolv.conf` `nameserver` lines; IPv6 support = any non-loopback interface address that `.To4() == nil`.

Tests: pure parsing helpers — `parseProcNetRoute(sampleText) (string, error)` and `parseResolvConf(sampleText) []string`.

- [x] Write netinfo files, wire main.go, run gates, commit.

## Task 5: `speedtest dns [--domains ...] [--servers ...]` — resolver comparison

**Files:**
- Create: `internal/dnsbench/dnsbench.go`
- Create: `internal/dnsbench/dnsbench_test.go`
- Modify: `main.go`

**Interfaces:**
- Produces: `dnsbench.RunDNS(args []string) error`, `dnsbench.Bench(domains, servers []string, timeout time.Duration) []dnsbench.ServerResult`, `dnsbench.ServerResult{Server string, AvgMs, MinMs, MaxMs float64, Failures int}`, `dnsbench.DefaultServers map[string]string` (label→addr: системный="", Cloudflare=1.1.1.1, Google=8.8.8.8, Quad9=9.9.9.9, Yandex=77.88.8.8, AdGuard=94.140.14.14, OpenDNS=208.67.222.222), `dnsbench.DefaultDomains []string`

Logic: per server, build a `net.Resolver{PreferGo: true, Dial: func(...) {dial udp to server+":53"}}` (empty server string = nil Dial → system resolver); for each domain, time `resolver.LookupHost(ctx, domain)`; collect durations, failures counted and excluded from avg/min/max (or counted as timeout = full timeout duration, document choice: exclude from avg, show failure count separately per Review Focus). Print a table, label rows by server name.

Tests: `summarizeDurations([]time.Duration, failures int) (avg, min, max float64)` pure function test.

- [x] Write dnsbench files, wire main.go, run gates, commit.

## Task 6: `speedtest bloat <host>` — bufferbloat test

**Files:**
- Create: `internal/bloat/bloat.go`
- Create: `internal/bloat/bloat_test.go`
- Modify: `main.go`

**Interfaces:**
- Produces: `bloat.RunBloat(args []string) error`, `bloat.Grade(increaseMs float64) string` (pure, A–F), `bloat.Result{Host string, BaselineMs, LoadedMs, IncreaseMs float64, Grade string}`

Logic: reuse `ping.Probe`/`ping.NormalizeHost` (port 80 default, `--port` override) for baseline latency (fixed count, e.g. 10 samples before load); start a background download via `webspeed.Download` against `--download-host` (default: same host) for `--duration` (default 10s); concurrently keep TCP-pinging the original host throughout the download; compare average loaded latency vs baseline; `Grade`: `<5` → "A", `<30` → "B", `<60` → "C", `<200` → "D", else "F" (document thresholds ms in a comment, loosely modeled on common bufferbloat grading scales).

Tests: `Grade` table test covering boundary values (4.9/5/29.9/30/59.9/60/199.9/200/500).

- [x] Write bloat files, wire main.go, run gates, commit.

## Task 7: TUI tabs — DNS, Инфо, TLS

**Files:**
- Create: `internal/tui/tab_dns.go`
- Create: `internal/tui/tab_info.go`
- Create: `internal/tui/tab_tls.go`
- Modify: `internal/tui/app.go` (register the three new tabs in `New()`)

**Interfaces:**
- Consumes: `dnsbench.Bench`, `dnsbench.DefaultDomains`, `dnsbench.DefaultServers`; `netinfo.Gather`; `tlsinfo.Inspect`; existing `tab` interface, `listen`, `styles.frame` helpers from `components.go`/`theme.go`.

Logic: follow `tab_httpdl.go` exactly — `tab_tls.go` has a `textinput` for host, Enter starts `tlsinfo.Inspect` in a goroutine streaming one result message; `tab_dns.go` has no input (defaults only), Enter runs `dnsbench.Bench` in a goroutine, renders a table as rows arrive or all at once on completion; `tab_info.go` has no input, runs `netinfo.Gather` automatically on `Init()` (like a one-shot), renders sections (external, interfaces, gateway, DNS, IPv6). Each tab gets a one-line `Title()` ("DNS", "Инфо", "TLS") and a `ShortHelp()`.

- [x] Write the three tab files, register in app.go, run gates (`go build ./... && go vet ./... && go test ./...`, `gofmt -l .`), commit.
