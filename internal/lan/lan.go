// Package lan measures raw TCP throughput between two machines on a local
// network. One side runs `lan server`, the other runs `lan client <host>`.
//
// Wire protocol (after connect, client sends a 9-byte header):
//
//	byte 0     : command  'D' (server -> client) or 'U' (client -> server)
//	byte 1..8  : big-endian uint64 payload length in bytes
//
// For 'D' the server then streams length zero-bytes to the client.
// For 'U' the client then streams length zero-bytes to the server, which
// drains them. This keeps both directions symmetric and dependency-free.
package lan

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"speedtest/internal/util"
)

const defaultAddr = ":5201"
const defaultPort = "5201"

// Phase identifies a stage of the client run for live Progress updates.
type Phase int

const (
	PhaseLatency Phase = iota
	PhaseDownload
	PhaseUpload
	PhaseDone
)

// Progress is a live update from a streaming client run (for the TUI).
type Progress struct {
	Phase     Phase
	Mbps      float64
	LatencyMs float64
}

// ClientOptions configures a streaming LAN client run.
type ClientOptions struct {
	Host  string // host or host:port (defaultPort fills a missing port)
	Bytes int64  // payload per direction
}

// ClientResult is the outcome of a streaming client run.
type ClientResult struct {
	Target       string  `json:"target"`
	LatencyMs    float64 `json:"latency_ms"`
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
}

// RunClient performs latency + download + upload against a LAN server, calling
// cb (may be nil) with live Progress. Shares the wire protocol and helpers with
// the headless runClient; the TUI dashboard uses this variant.
func RunClient(ctx context.Context, opt ClientOptions, cb func(Progress)) (ClientResult, error) {
	host := opt.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, defaultPort)
	}
	res := ClientResult{Target: host}

	ping, err := measureLatency(host, 5)
	if err != nil {
		return res, fmt.Errorf("подключение: %w", err)
	}
	res.LatencyMs = ping
	if cb != nil {
		cb(Progress{Phase: PhaseLatency, LatencyMs: ping})
	}

	runPhase := func(cmd byte, phase Phase) (time.Duration, error) {
		var cnt atomic.Int64
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(100 * time.Millisecond)
			defer t.Stop()
			last, lastT := int64(0), time.Now()
			for {
				select {
				case <-done:
					return
				case now := <-t.C:
					cur := cnt.Load()
					dt := now.Sub(lastT).Seconds()
					if dt > 0 && cb != nil {
						cb(Progress{Phase: phase, Mbps: float64(cur-last) * 8 / dt / 1e6})
					}
					last, lastT = cur, now
				}
			}
		}()
		dur, err := transferCtx(ctx, host, cmd, opt.Bytes, &cnt)
		close(done)
		return dur, err
	}

	down, err := runPhase('D', PhaseDownload)
	if err != nil {
		return res, notASpeedtestServer(host, err)
	}
	res.DownloadMbps = util.Mbps(opt.Bytes, down)

	up, err := runPhase('U', PhaseUpload)
	if err != nil {
		return res, notASpeedtestServer(host, err)
	}
	res.UploadMbps = util.Mbps(opt.Bytes, up)

	if cb != nil {
		cb(Progress{Phase: PhaseDone})
	}
	return res, nil
}

// transferCtx is transfer with a context and a live byte counter.
func transferCtx(ctx context.Context, host string, cmd byte, size int64, cnt *atomic.Int64) (time.Duration, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", host)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := writeHeader(conn, cmd, uint64(size)); err != nil {
		return 0, err
	}
	start := time.Now()
	switch cmd {
	case 'D':
		if _, err := io.CopyN(countSink{cnt}, conn, size); err != nil {
			return 0, err
		}
	case 'U':
		if _, err := io.CopyN(conn, countSource{zeroReader{}, cnt}, size); err != nil {
			return 0, err
		}
	}
	return time.Since(start), nil
}

// countSink discards bytes while counting them (download drain).
type countSink struct{ n *atomic.Int64 }

func (c countSink) Write(p []byte) (int, error) { c.n.Add(int64(len(p))); return len(p), nil }

// countSource wraps a reader and counts bytes read (upload source).
type countSource struct {
	r io.Reader
	n *atomic.Int64
}

func (c countSource) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n.Add(int64(k))
	return k, err
}

// Run dispatches `lan server` / `lan client`.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("использование: speedtest lan server|client ...")
	}
	switch args[0] {
	case "server":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:])
	default:
		return fmt.Errorf("неизвестная подкоманда lan %q (нужно server|client)", args[0])
	}
}

// ServerInfo describes a running embedded LAN-test server.
type ServerInfo struct {
	Port  string   // the bound TCP port
	Addrs []string // local "ip:port" addresses a client can connect to
}

// Serve starts a LAN-test server on addr (":5201" when empty) and accepts
// connections in the background until ctx is canceled. It returns immediately
// with the bound port and local addresses so a UI can show how to connect.
// The TUI's Локалка tab uses this so the user need not run `lan server`
// separately; the headless runServer drives it too.
func Serve(ctx context.Context, addr string) (ServerInfo, error) {
	if addr == "" {
		addr = defaultAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return ServerInfo{}, err
	}

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	info := ServerInfo{Port: port}
	for _, ip := range localIPs() {
		info.Addrs = append(info.Addrs, net.JoinHostPort(ip, port))
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return // listener closed via ctx — clean shutdown
				}
				// Unexpected failure: surface it instead of dying silently so a
				// broken listener isn't mistaken for a graceful stop.
				fmt.Fprintf(os.Stderr, "lan: приём соединения не удался: %v\n", err)
				return
			}
			go serve(conn)
		}
	}()
	return info, nil
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("lan server", flag.ContinueOnError)
	addr := fs.String("addr", defaultAddr, "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	info, err := Serve(ctx, *addr)
	if err != nil {
		return err
	}

	fmt.Printf("Сервер LAN-теста слушает порт %s\n", info.Port)
	fmt.Println("На другом устройстве запустите одну из команд:")
	for _, a := range info.Addrs {
		fmt.Printf("    speedtest lan client %s\n", a)
	}
	fmt.Println("Жду подключений... (Ctrl+C — остановить)")

	<-ctx.Done()
	return nil
}

func serve(conn net.Conn) {
	defer conn.Close()
	cmd, length, err := readHeader(conn)
	if err != nil {
		return
	}
	switch cmd {
	case 'D': // client wants to download: send `length` bytes
		io.CopyN(conn, zeroReader{}, int64(length))
	case 'U': // client uploads: drain `length` bytes
		io.CopyN(io.Discard, conn, int64(length))
	}
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("lan client", flag.ContinueOnError)
	sizeStr := fs.String("bytes", "100MB", "bytes to transfer per direction")
	asJSON := fs.Bool("json", false, "output result as JSON")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest lan client <host[:port]>")
	}
	host := pos[0]
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "5201")
	}
	size, err := util.ParseSize(*sizeStr)
	if err != nil {
		return err
	}

	if !*asJSON {
		fmt.Printf("Цель: %s   объём: %s в каждую сторону\n", host, util.Bytes(size))
	}

	ping, err := measureLatency(host, 5)
	if err != nil {
		return fmt.Errorf("подключение: %w", err)
	}
	if !*asJSON {
		fmt.Printf("Задержка: %.2f мс\n", ping)
	}

	down, err := transfer(host, 'D', size)
	if err != nil {
		return notASpeedtestServer(host, err)
	}
	if !*asJSON {
		fmt.Printf("Загрузка: %.2f Мбит/с\n", util.Mbps(size, down))
	}

	up, err := transfer(host, 'U', size)
	if err != nil {
		return notASpeedtestServer(host, err)
	}
	if !*asJSON {
		fmt.Printf("Отдача:   %.2f Мбит/с\n", util.Mbps(size, up))
		return nil
	}

	res := struct {
		Target       string  `json:"target"`
		LatencyMs    float64 `json:"latency_ms"`
		DownloadMbps float64 `json:"download_mbps"`
		UploadMbps   float64 `json:"upload_mbps"`
	}{host, ping, util.Mbps(size, down), util.Mbps(size, up)}
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
	return nil
}

// notASpeedtestServer turns a raw transfer failure into an explanation the
// user can act on: the target is reachable but is not running our LAN server.
func notASpeedtestServer(host string, err error) error {
	return fmt.Errorf(
		"%s ответил не как speedtest-сервер (%v).\n"+
			"  Для LAN-теста ЭТА программа должна быть запущена на другой машине:\n"+
			"    1. на %s выполните:  speedtest lan server\n"+
			"    2. затем наведите клиент на неё (порт по умолчанию 5201, не случайный открытый порт)",
		host, err, hostOnly(host))
}

// hostOnly strips the :port from a host:port string for display.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// transfer opens a connection, issues one command and times the payload.
func transfer(host string, cmd byte, size int64) (time.Duration, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if err := writeHeader(conn, cmd, uint64(size)); err != nil {
		return 0, err
	}

	start := time.Now()
	switch cmd {
	case 'D':
		if _, err := io.CopyN(io.Discard, conn, size); err != nil {
			return 0, err
		}
	case 'U':
		if _, err := io.CopyN(conn, zeroReader{}, size); err != nil {
			return 0, err
		}
	}
	return time.Since(start), nil
}

// measureLatency returns the median TCP connect RTT in ms over n attempts.
func measureLatency(host string, n int) (float64, error) {
	best := 1e9
	var ok bool
	for range n {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", host, 2*time.Second)
		if err != nil {
			continue
		}
		rtt := time.Since(t0).Seconds() * 1000
		conn.Close()
		ok = true
		best = min(best, rtt)
	}
	if !ok {
		return 0, fmt.Errorf("no successful connection to %s", host)
	}
	return best, nil
}

func writeHeader(w io.Writer, cmd byte, length uint64) error {
	var h [9]byte
	h[0] = cmd
	binary.BigEndian.PutUint64(h[1:], length)
	_, err := w.Write(h[:])
	return err
}

func readHeader(r io.Reader) (byte, uint64, error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, 0, err
	}
	return h[0], binary.BigEndian.Uint64(h[1:]), nil
}

// localIPs returns this machine's non-loopback IPv4 addresses so the user
// knows what address to type on the other device. The routable (internet-
// preferred) interface is listed first.
func localIPs() []string {
	preferred := ""
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			preferred = ua.IP.String()
		}
		conn.Close()
	}

	var ips []string
	if preferred != "" {
		ips = append(ips, preferred)
	}
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			s := ip4.String()
			if s != preferred {
				ips = append(ips, s)
			}
		}
	}
	if len(ips) == 0 {
		ips = []string{"<this-machine-ip>"}
	}
	return ips
}

// zeroReader is an infinite source of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
