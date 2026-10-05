# Security Toolkit Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 14 new capabilities to the `speedtest` network toolkit, oriented toward the diploma theme "микросервисная система обеспечения безопасности сетевой инфраструктуры" (security audit + testing + Wazuh monitoring). Each gets its own `internal/<pkg>` package with a pure/testable core plus a `Run<X>(args []string) error` CLI entry point, wired into `main.go`'s usage string and switch, each its own commit behind build/vet/test/fmt gates.

**Architecture:** Follow the established pattern (`internal/tlsinfo`, `internal/dnsbench`): a pure core function returning a `Result` struct (JSON-tagged), a `Run<X>` CLI wrapper using `util.ParseFlags`, Russian user-facing output, `--json` where there is a clean struct. A shared `internal/report` package (Task 1) lets every tool append a structured JSON line that a Wazuh agent ingests via `<localfile>`.

**Tech Stack:** Go stdlib only (`net`, `crypto/tls`, `net/http`, `encoding/json`, `flag`, UDP for mDNS/SSDP/DHCP/SNMP/NTP, `syscall`/`golang.org/x/sys` for raw sockets where needed) + existing `speedtest/internal/util`. No new third-party deps unless a task note says otherwise. The passive sniffer (Task 13) is the one high-risk item and may require a platform-gated raw-socket implementation.

## Global Constraints

- All user-facing CLI/TUI output in Russian, matching existing commands' tone.
- `--json` flag wherever the command has a clean result struct.
- `--wazuh` flag (or always-on) emits one `report.Event` JSON line to the report log for ingestion.
- Unit tests only for pure logic (parsing, grading, formatting) — no tests that need real network access.
- Run `go build ./... && go vet ./... && go test ./...` and `gofmt -l .` before every commit; fix before committing.
- Do NOT stage `internal/portscan/ports.go`, `internal/portscan/scan.go`, `internal/portscan/banner.go` into these commits (pre-existing uncommitted work, out of scope) — except Task 5 (CVE) may READ `GrabBanner` output, not edit it.
- One capability per commit, in the order below.

---

## Task 1: `internal/report` — shared Wazuh JSON emitter (foundation, #14)
Produces `report.Event{Time, Tool, Target, Severity, Summary string, Data map[string]any}`, `report.Emit(ev Event) error` (append JSONL to config-dir `security.jsonl`, overridable via `SPEEDTEST_REPORT_LOG`), `report.Path()`. Severity levels: info/low/medium/high/critical. Tests: path building, event marshaling, severity validation.

## Task 2: `speedtest headers <url>` — HTTP security headers audit (#1)
`internal/httphdr`. Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie Secure/HttpOnly/SameSite. Pure `Grade(findings) string` A–F. Emits report event. Tests: grading + header-presence scoring pure funcs.

## Task 3: `speedtest dnssec <domain>` — DNS security audit (#2, #5)
`internal/dnssec`. SPF, DMARC, DKIM (common selectors), DNSSEC (DS/RRSIG presence via DoH JSON to avoid a DNS-lib dep), CAA records, open-resolver check, AXFR zone-transfer attempt against the domain's NS. Pure parsers for SPF/DMARC/CAA record strings. Tests: record-string parsers.

## Task 4: `speedtest tlsaudit <host[:port]>` — deep TLS audit (#3)
`internal/tlsaudit` (new pkg, do not edit `tlsinfo`). Enumerate supported TLS versions (1.0–1.3) and weak ciphers by dialing with constrained `tls.Config`; flag self-signed, expired, weak-chain, SHA1. Pure `rate(findings) string` A–F. Tests: version/cipher classification pure funcs.

## Task 5: `speedtest cvecheck <ip>` — service version vs known-CVE hints (#4)
`internal/cvecheck`. Parse product+version out of banner strings (reuse portscan `GrabBanner` read-only), match against a small bundled JSON of known-vulnerable version ranges (offline, documented as indicative not authoritative). Tests: banner→(product,version) parser, version-range matcher.

## Task 6: `speedtest mdns` — mDNS/SSDP/Bonjour LAN discovery (#6)
`internal/mdns`. Send mDNS query (224.0.0.251:5353) + SSDP M-SEARCH (239.255.255.250:1900) UDP, collect responders (name, IP, service/USN). Tests: SSDP response header parser, mDNS name decode helper.

## Task 7: `speedtest dhcp` — DHCP server discovery (#7)
`internal/dhcp`. Broadcast DHCPDISCOVER (UDP 68→67), collect DHCPOFFER responses, flag multiple/rogue servers. Pure DHCP packet build + offer parse. Tests: build/parse round-trip.

## Task 8: `speedtest snmp <host>` — SNMP inventory (#8)
`internal/snmp`. SNMPv2c GET of sysDescr/sysName/sysUpTime with `public` (configurable `--community`), BER/ASN.1 encode/decode by hand (no dep). Tests: BER length encode/decode, OID encode, varbind parse.

## Task 9: `speedtest snapshot` / diff tracking (#9) — highest value for Wazuh
`internal/snapshot`. Persist a normalized snapshot of a discover/scan result; on next run, diff against the last stored snapshot for the same scope and emit report events for: new host, new open port, port closed, cert changed. Pure `Diff(old, new Snapshot) []Change`. Tests: diff logic across added/removed/changed.

## Task 10: `speedtest mtu <host>` — path MTU discovery (#10)
`internal/mtu`. Binary-search the largest payload that arrives without fragmentation (DF bit). Linux: `IP_MTU_DISCOVER`/`IP_MTU` via `golang.org/x/sys/unix` (already indirect dep? else build-tagged). Pure search-bounds helper. Tests: search-step pure func.

## Task 11: `speedtest ntp <server>` — NTP check (#11)
`internal/ntp`. SNTP client (UDP 123), compute offset + round-trip, flag unreachable/large offset. Pure NTP timestamp<->time conversion. Tests: timestamp conversion round-trip, offset math.

## Task 12: `speedtest uptime <targets...>` — scheduled uptime monitor (#13)
`internal/uptime`. Repeatedly TCP-probe targets on an interval, track up/down transitions and cumulative uptime %, emit report events on state change. Pure state-machine (probe result → transition). Tests: transition/uptime-accounting pure func.

## Task 13: `speedtest sniff` — passive traffic stats (#12, highest risk)
`internal/sniff`. Capture packets on an interface, aggregate per-protocol / per-host byte counts (metadata only, never payload). Linux AF_PACKET raw socket via `golang.org/x/sys/unix`, build-tagged `linux`; `!linux` stub returns a clear "unsupported" error. Requires `CAP_NET_RAW`. Pure Ethernet/IP header parser (fixed byte offsets). Tests: header parser on crafted byte slices.

## Task 14: wire remaining tools into TUI + `menu` + README (#visibility)
Add menu entries and, where it fits the one-shot/streaming tab pattern, TUI tabs for the new read-only tools (headers, dnssec, tlsaudit, info already exists). Update `main.go` usage and `README.md` with the security-toolkit section and the Wazuh ingestion note.

---

## Review Focus
- Every network tool must degrade gracefully (timeout, unreachable, refused) with a clear Russian error, never a panic.
- Scanning/discovery tools: document that they are for networks you own or are authorized to test.
- `report.Emit` must never crash a tool if the log is unwritable — best-effort, log-and-continue.
- Raw-socket tools (sniff, mtu, dhcp) must fail clearly when lacking privileges, not silently do nothing.
