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
| **Скан** / `scan` | TCP (and optional UDP) port scan of a single host with a live progress bar; `--banner` service detection, web fingerprint of open HTTP ports, and — for a domain with open ports — a subdomain search (DNS/MX/NS, TLS certs, crt.sh). |
| **Скан сети** / `discover` | Sweep the local subnet: live hosts, open ports, hostname, MAC, vendor. |
| **Аудит** / `audit` | Security audit of a host: TLS/certificate, HTTP security headers, exposed risky ports → A–F grade. |
| **Wi-Fi** / `wifi` | Wi-Fi survey: current SSID/signal/channel, nearby networks, least-congested 2.4 GHz channel advice. |
| **Полоса** / `bwmon` | This machine's live per-interface throughput (rx/tx) from OS byte counters. |
| **Снифер** / `sniff` | Passive top-talkers by traffic volume (needs a `pcap` build + Npcap/libpcap). |
| **Монитор** / `monitor` | Continuous checks (ping/port-drift/audit-grade/bandwidth) with alerts on breach → stdout/webhook/desktop/history. |
| **История** / `history` | Every run is saved automatically; trend sparkline + CSV/JSON export. |

## The TUI dashboard

```sh
speedtest            # launch the full-screen dashboard
```

- **Tab / Shift+Tab** or **1-9, 0** — switch tabs (0 = 10th), **← →** / **h l** also work.
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
speedtest scan example.com                              # names resolve once, up front
speedtest scan example.com --web                         # only web ports + fingerprint them
speedtest scan example.com --udp common                  # also sweep the common UDP services
speedtest scan example.com --subdomains=false --no-ct    # skip subdomain / crt.sh lookups
speedtest discover                       # auto-detect local /24
speedtest discover --cidr 10.0.0.0/24 --ports 22,80,443,3389 --json
speedtest discover --cidr 192.168.20.0/24,192.168.100.0/24   # several subnets at once
speedtest discover --all-subnets         # every attached subnet (interfaces + routes)
speedtest discover --expand              # auto-find subnets (traceroute) and scan them
speedtest discover --cidr 192.168.100.0/24 --expand --snmp-community public
speedtest discover --no-icmp             # liveness by TCP/ARP only, no ping probes
```
Discovery does a fast liveness pre-check, then deep-scans only live hosts and
annotates each with reverse-DNS name, MAC and vendor (system ARP table + OUI).
`--cidr` accepts a comma-separated list.

**Liveness** combines three independent signals, so a host is found even when it
answers only one of them: the system **ARP cache** (an L2 neighbour with a real
unicast MAC exists — read before *and* after probing, since the probes themselves
resolve addresses), an **ICMP echo** (sent without administrator/root, same
mechanism as the traceroute), and the **TCP** liveness ports (a SYN-ACK *or* a
RST both prove the host is there). `--no-icmp` drops the ping probe for networks
that rate-limit or block ICMP; `--all` skips the pre-check entirely and
deep-scans every address in the range.

**Auto-discovering subnets you don't know about** — `--all-subnets` only sees
subnets in this machine's routing table. `--expand` goes further: it traceroutes
to live hosts to reveal transit routers (each hop hints at a subnet) and, when
`--snmp-community` is given, walks each gateway's interface table over SNMP to
learn every subnet that router bridges. New subnets are scanned recursively up to
`--expand-depth` (default 2). Everything is read-only; unreachable gateways and
closed SNMP agents simply contribute nothing.

**In the TUI**, the **Скан сети** tab is a plain menu — pick a scope with ↑/↓ and
press Enter:

- **Моя сеть** — the subnet this computer is on.
- **Все мои сети** — every attached subnet (interfaces + routes).
- **Выбрать сети вручную** — type a comma-separated CIDR list.
- **Найти все сети** — the `--expand` sweep; optional fields for seed subnets, an
  SNMP community (for the full router-table map) and search depth.

`[i]` toggles the ICMP-пинг probe for any of the four scopes (the CLI's
`--no-icmp`). The results table carries the MAC alongside the vendor, so a device
found by its ARP entry alone — no open port, no reverse-DNS name — is still
identifiable.
`scan --banner` reads the greeting each open port volunteers (SSH/FTP/SMTP) or
the HTTP `Server` header, revealing the running software and version.

**Scanning by name** — a hostname is resolved once before the scan and every
port is then dialled at that one address, so a round-robin or CDN name can't
answer each connection with a different server. The address is printed next to
the name (`example.com (93.184.216.34)`), an unresolvable name is an error
rather than an empty result, and a name that local DNS filtering points at
`127.0.0.1` is called out — otherwise the scanner reports its own open ports.

**Subdomain search** — when a named host turns out to have open ports, the zone
is searched for its other names (skip with `--subdomains=false`). Four sources,
none needing an API key: a dictionary of ~250 common labels resolved against DNS,
the zone's own MX/NS/CNAME records, the names listed in the TLS certificates
served on the open ports, and the Certificate Transparency logs via crt.sh
(`--no-ct` to skip). CT is the deepest source — every certificate a CA ever
issued for the zone is public — and finds internal/staging/decommissioned hosts a
dictionary never would; it is best-effort, so a crt.sh outage just contributes
nothing. Names from certificates and CT are not resolved by default (they prove a
name existed, not that it points anywhere today); add `--resolve-subs` to look
them up. Wildcard DNS is detected first, so a catch-all zone doesn't report the
whole dictionary as real hosts.

**UDP scan** — `--udp <ports|common>` sweeps UDP alongside the TCP scan. UDP is
connectionless, so results are three-valued: `open` (the service replied to a
protocol-specific probe — DNS, NTP, SNMP, NetBIOS, SSDP, IKE, mDNS, …), `closed`
(an ICMP port-unreachable came back), or `open|filtered` (silence, which is
either an open service that ignored the probe or a firewall dropping the packet).
Only the interesting (non-closed) ports are shown. Analogous to `nmap -sU`.

**Web fingerprint** — every open web port is fetched once (`--fingerprint`, on by
default; `--web` scans only web ports and turns it on): the status code, any
redirect, the `Server` header, the page `<title>`, and the technologies inferred
from headers and body (nginx/Apache/IIS, PHP/ASP.NET/Express/Next.js, WordPress/
Drupal/Joomla, React/Vue/Angular, Grafana/Kibana/Jenkins, …). This is the local,
no-dependency equivalent of `whatweb`/`httpx`. The TLS certificate is read but
not trusted, so an expired or self-signed cert still gets fingerprinted.

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

### Wi-Fi survey
```sh
speedtest wifi
speedtest wifi --json
```
Shows the current connection (SSID, signal, channel), nearby networks, and which
2.4 GHz channel is least congested. Per-client traffic is **not** shown — that
needs the adapter in monitor mode.

### Bandwidth monitor (this host)
```sh
speedtest bwmon --interval 2s
speedtest bwmon --count 5 --json
```
Live receive/transmit throughput per interface, from OS counters
(`Get-NetAdapterStatistics` on Windows, `/proc/net/dev` on Linux, `netstat -ib`
on macOS). It measures **this machine only** — seeing other devices' traffic
needs the router's cooperation or a capture vantage.

### Passive top-talkers (pcap)
```sh
go build -tags pcap -o speedtest .        # requires Npcap (Windows) / libpcap
speedtest sniff --top 15 --resolve
speedtest sniff --iface "Wi-Fi" --json
```
Ranks who is "talking" most by captured traffic volume. On a switched network you
mostly see your own traffic plus broadcast; a full picture needs a SPAN port or
Wi-Fi monitor mode. Without the `pcap` build tag the command is unavailable.

### Continuous monitoring & alerts
```sh
speedtest monitor init                    # write a sample monitor.yaml
speedtest monitor check                   # one pass; non-zero exit on any breach
speedtest monitor run                      # loop, each check on its own interval
```
Turns the one-shot probes into continuous checks that alert on threshold breach
or drift. `check` is built for cron/CI (its exit code reflects breaches); `run`
is a long-lived daemon. Both read the same YAML and share the alert sinks.

Checks: **ping** (latency/loss), **portdrift** (a port opened or closed vs. the
last baseline), **auditgrade** (security grade dropped below a minimum or new
findings appeared), **bandwidth** (rx/tx over a threshold). Sinks: **stdout**
(+exit code), **webhook** (POST JSON with a `text` field, so Slack/Discord
incoming webhooks render it), **desktop** (native OS toast), **history** (breaches
saved alongside measurements).

```yaml
# monitor.yaml
checks:
  - {type: ping,       target: 1.1.1.1,     interval: 10s, max_latency: 80ms, max_loss: 5}
  - {type: portdrift,  target: 192.168.1.1, interval: 5m,  ports: 1-1024}
  - {type: auditgrade, target: example.com, interval: 1h,  min_grade: B}
  - {type: bandwidth,  iface: "",           interval: 2s,  max_mbps: 900}
sinks:
  stdout: true
  webhook: ""            # e.g. https://hooks.slack.com/services/...
  desktop: false
  history: true
```

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
