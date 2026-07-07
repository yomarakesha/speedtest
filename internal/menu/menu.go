// Package menu provides an interactive text menu shown when speedtest is
// launched with no arguments. It gathers parameters, then calls the same
// command entrypoints the flags-based CLI uses.
package menu

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"speedtest/internal/lan"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
)

const banner = `
  ███ speedtest — network toolkit
  ────────────────────────────────`

const menu = `
  1) Internet speed test        (download / upload / ping)
  2) LAN speed test  - client   (measure to another machine)
  3) LAN speed test  - server   (run here, others connect)
  4) Ping any device - latency   (works on any IP, no agent)
  5) Port scan       - one IP   (which ports are open)
  6) Discover subnet - open ports per host on your LAN
  7) Help
  0) Exit
`

var in = bufio.NewScanner(os.Stdin)

// Run shows the interactive loop until the user exits.
func Run() error {
	fmt.Println(banner)
	for {
		fmt.Print(menu)
		choice, ok := prompt("Choose", "")
		if !ok { // stdin closed / EOF
			fmt.Println("\nBye.")
			return nil
		}
		if choice == "" {
			continue
		}
		fmt.Println()

		var err error
		switch choice {
		case "1":
			err = speedtest.RunInternet(nil)
		case "2":
			err = lanClient()
		case "3":
			err = lanServer()
		case "4":
			err = pingHost()
		case "5":
			err = scan()
		case "6":
			err = discover()
		case "7":
			printHelp()
		case "0", "q", "quit", "exit":
			fmt.Println("Bye.")
			return nil
		default:
			fmt.Printf("Unknown choice %q\n", choice)
			continue
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		pause()
	}
}

func lanClient() error {
	host, _ := prompt("Server host (ip[:port])", "")
	if host == "" {
		return fmt.Errorf("host required")
	}
	bytes, _ := prompt("Bytes per direction", "100MB")
	return lan.Run([]string{"client", host, "--bytes", bytes})
}

func lanServer() error {
	addr, _ := prompt("Listen address", ":5201")
	fmt.Println("Starting server. Press Ctrl+C to stop.")
	return lan.Run([]string{"server", "--addr", addr})
}

func pingHost() error {
	host, _ := prompt("Target host/IP", "")
	if host == "" {
		return fmt.Errorf("host required")
	}
	port, _ := prompt("Port to probe", "80")
	count, _ := prompt("Attempts", "5")
	return ping.RunPing([]string{host, "--port", port, "--count", count})
}

func scan() error {
	ip, _ := prompt("Target IP", "")
	if ip == "" {
		return fmt.Errorf("IP required")
	}
	ports, _ := prompt("Ports (e.g. 22,80,443 or 1-1024)", "1-1024")
	return portscan.RunScan([]string{ip, "--ports", ports})
}

func discover() error {
	cidr, _ := prompt("Subnet CIDR (blank = auto-detect)", "")
	ports, _ := prompt("Ports (blank = common services)", "")
	args := []string{}
	if cidr != "" {
		args = append(args, "--cidr", cidr)
	}
	if ports != "" {
		args = append(args, "--ports", ports)
	}
	return portscan.RunDiscover(args)
}

func printHelp() {
	fmt.Print(`
  Internet   Measures your internet link against Yandex CDN nodes.
  LAN client Connects to a "LAN server" on another machine and times
             a raw TCP transfer in both directions.
  LAN server Run this on the target machine first, then use LAN client
             from another machine pointing at this machine's IP.
  Ping       TCP-connect latency to ANY device (min/avg/max, loss).
             No software needed on the target - unlike LAN speed test.
  Port scan  TCP connect() scan of one host; lists ports that accept.
  Discover   Scans every host in a subnet and shows open ports per IP.

  Tip: you can also run commands directly, e.g.
       speedtest internet
       speedtest scan 192.168.1.1 --ports 1-65535
       speedtest discover --cidr 192.168.1.0/24
`)
}

// prompt prints "label [def]: " and returns (value, ok). ok is false when
// stdin is closed (EOF), so callers can stop instead of looping forever.
// An empty entry yields def.
func prompt(label, def string) (string, bool) {
	if def != "" {
		fmt.Printf("  %s [%s]: ", label, def)
	} else {
		fmt.Printf("  %s: ", label)
	}
	if !in.Scan() {
		return def, false
	}
	// Strip a leading UTF-8 BOM (piped input on Windows often prepends one).
	v := strings.TrimPrefix(in.Text(), string(rune(0xFEFF)))
	v = strings.TrimSpace(v)
	if v == "" {
		return def, true
	}
	return v, true
}

func pause() {
	fmt.Print("\n  -- press Enter to return to menu --")
	in.Scan()
	fmt.Println()
}
