// Command speedtest is a CLI network toolkit:
//   - internet: measure internet speed via the Yandex Internetometer API
//   - lan:      measure throughput to another host on the local network
//   - scan:     scan TCP ports on a single IP
//   - discover: sweep a subnet and report which hosts have which ports open
package main

import (
	"fmt"
	"os"

	"speedtest/internal/lan"
	"speedtest/internal/menu"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
)

const usage = `speedtest - CLI network toolkit

Run with no arguments to open an interactive menu.

Usage:
  speedtest internet [--json] [--attempts N]
        Measure internet download/upload/ping via Yandex Internetometer.

  speedtest lan server [--addr :5201]
        Run a LAN speedtest server (run this on the other machine).

  speedtest lan client <host[:port]> [--bytes 100MB] [--json]
        Measure download/upload/latency to a LAN speedtest server.

  speedtest ping <host[:port]> [--count 5] [--port 80] [--timeout 2s]
        Measure TCP-connect latency to any device (no agent needed).

  speedtest scan <ip> [--ports 1-1024] [--timeout 500ms] [--workers 500]
        Scan TCP ports on a single host and list the open ones.

  speedtest discover [--cidr 192.168.1.0/24] [--ports 22,80,443,...]
                     [--timeout 400ms] [--workers 1000]
        Sweep a subnet and show which IPs have which ports open.
        If --cidr is omitted the local /24 is auto-detected.

Global:
  -h, --help    Show this help.
`

func main() {
	// No arguments -> launch the interactive menu.
	if len(os.Args) < 2 {
		if err := menu.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "internet":
		err = speedtest.RunInternet(args)
	case "lan":
		err = lan.Run(args)
	case "ping":
		err = ping.RunPing(args)
	case "scan":
		err = portscan.RunScan(args)
	case "discover":
		err = portscan.RunDiscover(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
