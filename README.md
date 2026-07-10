# speedtest

A full-screen, live-updating **network toolkit** for the terminal, written in Go.
Launch it with no arguments and you get a cinematic TUI dashboard; every tool is
also available as a scriptable subcommand. The interface is in Russian.

![CI](https://github.com/yomarakesha/speedtest/actions/workflows/ci.yml/badge.svg)

## What it does

| Tab / command | What it measures |
|---|---|
| **Интернет** / `internet` | Internet download / upload / ping via the public [Yandex Internetometer](https://yandex.ru/internet) API, with live animated sparklines. |
| **Локалка** / `lan` | Raw TCP throughput to another machine running `lan server`. |
| **Пинг** / `ping` | TCP-connect latency to **any** device (no agent), gping-style live graph. |
| **Трейс** / `trace` | Traceroute + continuous per-hop ping (mtr/trippy-style), live loss & RTT. |
| **HTTP** / `httpdl` | Download speed from any device's own HTTP(S) server — no agent on target. |
| **Скан** / `scan` | TCP port scan of a single host with a live progress bar; optional `--banner` service detection. |
| **Обзор** / `discover` | Sweep the local subnet: live hosts, open ports, hostname, MAC, vendor. |
| **Аудит** / `audit` | Security audit of a host: TLS/certificate, HTTP security headers, exposed risky ports → A–F grade. |
| **История** / `history` | Every run is saved automatically; trend sparkline + CSV/JSON export. |

## The TUI dashboard

```sh
speedtest            # launch the full-screen dashboard
```

- **Tab / Shift+Tab** or **1-9** — switch tabs, **← →** / **h l** also work.
- **?** — help overlay. **q** / **Ctrl+C** — quit.
- Each tab drives the same measurement engine as its headless command, so the
  numbers you see live are identical to what `--json` reports.

Traceroute sends real ICMP **without administrator/root**: on Windows via the IP
Helper API (`IcmpSendEcho`), on Linux/macOS via unprivileged ICMP datagram
sockets.

## Install / build

Requires Go 1.26+.

```sh
go build -o speedtest .      # or speedtest.exe on Windows
go test ./...
```

Pre-built binaries for Linux, macOS and Windows (amd64 + arm64) are attached to
each GitHub release (built with GoReleaser).

## Headless commands

Everything the dashboard does is available directly; add `--json` for
machine-readable output.

### Internet speed
```sh
speedtest internet
speedtest internet --json --attempts 5
```

### LAN speed
Run the server on one machine, the client on another:
```sh
speedtest lan server                 # listens on :5201
speedtest lan client 192.168.1.50 --bytes 500MB
```

### Ping any device
```sh
speedtest ping 192.168.1.1 --port 443 --count 10
```
TCP-connect time is the RTT, so any reachable port works. 100% loss usually just
means the probed port is filtered — try `--port 443`, `22`, `445`.

### Traceroute + ping
```sh
speedtest trace 8.8.8.8            # live table until Ctrl+C
speedtest trace ya.ru --json       # bounded run, JSON output
```
Shows per-hop loss and last/avg/best/worst RTT, refreshed every round.

### HTTP download (no agent)
```sh
speedtest httpdl http://192.168.1.10:8080/big.iso --duration 20s
```
Download-only estimate; accurate only against a large response.

### Port scan / subnet discovery
```sh
speedtest scan 192.168.1.1 --ports 1-65535 --workers 1000
speedtest scan 192.168.1.1 --ports 22,80,443 --banner   # grab service banners
speedtest discover                       # auto-detect local /24
speedtest discover --cidr 10.0.0.0/24 --ports 22,80,443,3389 --json
```
Discovery does a fast liveness pre-check, then deep-scans only live hosts and
annotates each with reverse-DNS name, MAC and vendor (system ARP table + OUI).
`scan --banner` reads the greeting each open port volunteers (SSH/FTP/SMTP) or
the HTTP `Server` header, revealing the running software and version.

### Security audit
```sh
speedtest audit example.com                 # TLS + HTTP headers + risky ports
speedtest audit example.com --json
speedtest audit example.com --export html > report.html
speedtest tlsaudit example.com              # TLS/certificate checks only
speedtest httpaudit https://example.com     # HTTP security headers only
```
Each check produces findings ranked by severity and an overall **A–F** grade:

- **TLS** — deprecated protocol versions (TLS 1.0/1.1), expired/soon-expiring or
  untrusted certificates, hostname mismatch, weak signature algorithms.
- **HTTP headers** — missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy; cookies without Secure/HttpOnly; version leakage in `Server`.
- **Ports** — exposed sensitive services (Telnet, SMB, RDP, VNC, Redis, MongoDB,
  databases, …); suppressed automatically when a host ACKs nearly every port
  (CDN/load-balancer/tarpit) to avoid false positives.

By default all checks are passive: they open normal connections and inspect what
the server volunteers. Audit runs are saved to history like every other
measurement.

Two opt-in flags add deeper probing:

```sh
speedtest audit ns.example.com --dns                     # open resolver + AXFR
speedtest audit 192.168.1.10 --i-have-authorization      # active checks
```

- `--dns` tests whether the host is an **open recursive resolver** and whether
  it permits an unauthenticated **zone transfer (AXFR)**.
- `--i-have-authorization` enables **active** checks that interact with services:
  default HTTP Basic credentials, unauthenticated Redis/Memcached/Elasticsearch,
  anonymous FTP, and CVE matching against grabbed banners. These send commands
  and try logins — **only run them against systems you are authorized to test.**
  The CVE table is a small illustrative set; treat hits as leads to verify.

### History & export
```sh
speedtest history                 # human-readable log
speedtest history --export csv    # or: json
```
Runs are appended to `history.jsonl` under your OS config dir
(`%AppData%\speedtest\` on Windows, `~/.config/speedtest/` on Linux,
`~/Library/Application Support/speedtest/` on macOS). The **История** tab shows a
download-speed trend and can export from inside the app (**c** = CSV, **j** = JSON).

### Text menu (no graphics)
```sh
speedtest menu       # simple line-based menu, for terminals without a TUI
```

## Dependencies

The dashboard uses the [Charm](https://charm.sh) stack — Bubble Tea, Lip Gloss,
Bubbles — plus [ntcharts](https://github.com/NimbleMarkets/ntcharts) for graphs,
and `golang.org/x/net` / `golang.org/x/sys` for the no-admin ICMP traceroute.
The measurement engines themselves remain small and standard-library-based.

## Notes

- Port scanning uses TCP `connect()`; accept-then-reset firewalls can produce
  false "open" results — treat virtual-adapter results with suspicion.
- Only scan and probe hosts and networks you are authorized to test.
