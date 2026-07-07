# speedtest

A dependency-free CLI network toolkit written in Go:

- **`internet`** — measure internet download / upload / ping via the public
  [Yandex Internetometer](https://yandex.ru/internet) API.
- **`lan`** — measure raw TCP throughput to another machine on your local network.
- **`ping`** — measure TCP-connect latency to **any** device (no agent needed).
- **`scan`** — scan TCP ports on a single IP.
- **`discover`** — sweep a subnet and report which hosts have which ports open.

Uses only the Go standard library — no external modules.

## Build

```sh
go build -o speedtest.exe .
```

## Interactive menu

Run with no arguments to get a menu that walks you through each tool:

```sh
speedtest.exe
```

```
  ███ speedtest — network toolkit
  ────────────────────────────────

  1) Internet speed test        (download / upload / ping)
  2) LAN speed test  - client   (measure to another machine)
  3) LAN speed test  - server   (run here, others connect)
  4) Port scan       - one IP   (which ports are open)
  5) Discover subnet - open ports per host on your LAN
  6) Help
  0) Exit
  Choose:
```

Each option prompts for its parameters (with sensible defaults in `[brackets]`).
Every menu action is also available directly as a subcommand — see below.

## Usage (direct commands)

### Internet speed

```sh
speedtest internet
speedtest internet --json            # machine-readable output
speedtest internet --attempts 5      # more ping samples
```

```
Ping...     18.3 ms
Download... 94.71 Mbps
Upload...   38.02 Mbps
```

Download and upload run three parallel streams against the nearest Yandex CDN
nodes and report combined throughput. The measurement window is capped at 30s
per direction, so on slow links the result is the sustained rate over that window.

### LAN speed

Run the server on one machine:

```sh
speedtest lan server                 # listens on :5201
speedtest lan server --addr :9000
```

Run the client on another (or the same) machine, pointing at the server's IP:

```sh
speedtest lan client 192.168.1.50
speedtest lan client 192.168.1.50 --bytes 500MB
speedtest lan client 192.168.1.50:9000
```

```
Target: 192.168.1.50:5201   payload: 500.00 MiB per direction
Latency:  0.42 ms
Download: 942.10 Mbps
Upload:   911.55 Mbps
```

Sizes accept `K`/`M`/`G` suffixes (powers of 1024); a bare number is bytes.

### Ping any device (latency)

Works against any host that has a reachable TCP port — no software needed on
the target. Uses TCP connect time as the round-trip measurement.

```sh
speedtest ping 192.168.1.1
speedtest ping 192.168.1.1 --port 443 --count 10
speedtest ping example.com:22
```

```
PING (TCP) 192.168.1.1:80  -  5 attempts
  seq 1: 2.31 ms
  seq 2: 1.98 ms
  ...
min 1.90 / avg 2.24 / max 3.11 ms   0% loss (5/5)
```

If a device shows 100% loss, try a port it actually has open (`--port 443`,
`22`, `445`, ...); a closed-but-reachable port still yields a valid RTT.

### Port scan (single host)

```sh
speedtest scan 192.168.1.1
speedtest scan 192.168.1.1 --ports 22,80,443
speedtest scan 10.0.0.5 --ports 1-65535 --timeout 800ms --workers 1000
```

```
PORT     STATE  SERVICE
22       open   ssh
80       open   http
443      open   https
```

### Subnet discovery (who has what open)

```sh
speedtest discover                                   # auto-detect local subnet
speedtest discover --cidr 192.168.1.0/24
speedtest discover --cidr 10.0.0.0/24 --ports 22,80,443,3389
speedtest discover --cidr 192.168.0.0/24 --timeout 400ms --workers 1500
```

```
HOST             OPEN PORTS
192.168.1.1      53(dns) 80(http) 443(https)
192.168.1.10     22(ssh) 445(smb) 3389(rdp)
192.168.1.42     80(http) 8080(http-proxy)
```

Without `--ports`, discovery scans a compact set of common service ports.
Without `--cidr`, the subnet of the interface your OS uses to reach the internet
is auto-detected. Subnets larger than /16 are rejected to avoid runaway scans.

## Notes

- Port scanning uses TCP connect() — it detects ports that **accept**
  connections. Some firewalls/NAT gateways accept-then-reset, which can show
  as false "open"; treat virtual-adapter results with suspicion.
- Only scan hosts and networks you are authorized to test.
