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
| `wol` | Wake-on-LAN: send a magic packet to wake a sleeping device. |
| **Скан** / `scan` | TCP port scan of a single host with a live progress bar. |
| **Обзор** / `discover` | Sweep the local subnet: live hosts, open ports, hostname, MAC, vendor. |
| **DNS** / `dns` | Compare response time across several DNS resolvers. |
| **Инфо** / `info` | External IP/ISP, local interfaces, default gateway, DNS servers, IPv6. |
| **TLS** / `tls` | TLS certificate inspection: issuer, validity, version, cipher, SANs. |
| `timing` | Per-stage HTTP timing breakdown: DNS, connect, TLS, TTFB, total. |
| `bloat` | Bufferbloat test: latency increase under load, graded A-F. |
| **История** / `history` | Every run is saved automatically; trend sparkline + CSV/JSON export. |

## The TUI dashboard

```sh
speedtest            # launch the full-screen dashboard
```

- **Tab / Shift+Tab** or **1-9, 0** — switch tabs, **← →** / **h l** also work.
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

### Wake-on-LAN
```sh
speedtest wol aa:bb:cc:dd:ee:ff --ip 192.168.1.255
```
Sends the magic packet via UDP broadcast; the target's NIC must have WoL enabled.

### TLS certificate inspection
```sh
speedtest tls example.com:443 --json
```
Connects without verifying the chain so even an expired or self-signed cert can
be inspected; validity is reported as a separate field.

### HTTP timing breakdown
```sh
speedtest timing https://example.com/
```
Per-stage breakdown of a single request: DNS, TCP connect, TLS handshake,
time-to-first-byte, total.

### Network information
```sh
speedtest info --json
```
External IP/ISP, local interfaces (IP/MAC), default gateway, system DNS
servers, IPv6 support.

### DNS resolver comparison
```sh
speedtest dns --domains ya.ru,github.com --servers Cloudflare=1.1.1.1,Google=8.8.8.8
```
Compares response time across the system resolver and well-known public ones.

### Bufferbloat test
```sh
speedtest bloat 192.168.1.1 --duration 15s
```
Baseline TCP-ping latency, then latency again during a concurrent download;
grades the increase A-F.

### Port scan / subnet discovery
```sh
speedtest scan 192.168.1.1 --ports 1-65535 --workers 1000
speedtest discover                       # auto-detect local /24
speedtest discover --cidr 10.0.0.0/24 --ports 22,80,443,3389 --json
```
Discovery does a fast liveness pre-check, then deep-scans only live hosts and
annotates each with reverse-DNS name, MAC and vendor (system ARP table + OUI).

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
