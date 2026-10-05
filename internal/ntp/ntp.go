// Package ntp is a minimal SNTP client: it queries an NTP server over UDP/123,
// computes the local clock's offset and the round-trip delay, and flags an
// unreachable server or a large offset. Useful for spotting time drift that
// breaks TLS validation, Kerberos, and log correlation.
package ntp

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"time"

	"speedtest/internal/report"
	"speedtest/internal/util"
)

// DefaultServer is queried when none is given.
const DefaultServer = "pool.ntp.org"

// ntpEpochOffset is the seconds between the NTP epoch (1900-01-01) and the Unix
// epoch (1970-01-01).
const ntpEpochOffset = 2208988800

// Result is the outcome of one NTP query.
type Result struct {
	Server    string    `json:"server"`
	ServerUTC time.Time `json:"server_utc"`
	OffsetMs  float64   `json:"offset_ms"`
	RTTMs     float64   `json:"rtt_ms"`
	Stratum   int       `json:"stratum"`
}

// toNTPTime converts seconds+fraction (NTP format) to a time.Time.
func toNTPTime(sec, frac uint32) time.Time {
	secs := int64(sec) - ntpEpochOffset
	nanos := (int64(frac) * 1e9) >> 32
	return time.Unix(secs, nanos).UTC()
}

// fromNTPTime converts a time.Time to NTP seconds+fraction.
func fromNTPTime(t time.Time) (sec, frac uint32) {
	unixNanos := t.UnixNano()
	secs := unixNanos/1e9 + ntpEpochOffset
	nanos := unixNanos % 1e9
	return uint32(secs), uint32((nanos << 32) / 1e9)
}

// offsetRTT computes clock offset and round-trip delay from the four SNTP
// timestamps. t1=client send, t2=server recv, t3=server send, t4=client recv.
// Returns milliseconds.
func offsetRTT(t1, t2, t3, t4 time.Time) (offsetMs, rttMs float64) {
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	rtt := t4.Sub(t1) - t3.Sub(t2)
	return float64(offset) / float64(time.Millisecond), float64(rtt) / float64(time.Millisecond)
}

// Query performs one SNTP exchange with server (host or host:port).
func Query(server string, timeout time.Duration) (Result, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "123")
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return Result{}, fmt.Errorf("подключение к %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, 48)
	req[0] = 0x23 // LI=0, VN=4, Mode=3 (client)

	t1 := time.Now()
	if _, err := conn.Write(req); err != nil {
		return Result{}, fmt.Errorf("отправка запроса: %w", err)
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return Result{}, fmt.Errorf("нет ответа: %w", err)
	}
	t4 := time.Now()

	stratum := int(resp[1])
	t2 := toNTPTime(binary.BigEndian.Uint32(resp[32:]), binary.BigEndian.Uint32(resp[36:]))
	t3 := toNTPTime(binary.BigEndian.Uint32(resp[40:]), binary.BigEndian.Uint32(resp[44:]))
	offsetMs, rttMs := offsetRTT(t1, t2, t3, t4)

	return Result{
		Server:    addr,
		ServerUTC: t3,
		OffsetMs:  offsetMs,
		RTTMs:     rttMs,
		Stratum:   stratum,
	}, nil
}

// RunNTP is the CLI entry point for `speedtest ntp [server]`.
func RunNTP(args []string) error {
	fs := flag.NewFlagSet("ntp", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "query timeout")
	maxOffset := fs.Duration("max-offset", time.Second, "offset above which to warn/flag")
	asJSON := fs.Bool("json", false, "output result as JSON")
	wazuh := fs.Bool("wazuh", false, "emit finding to the Wazuh report log")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	server := DefaultServer
	if len(pos) > 0 {
		server = pos[0]
	}

	res, err := Query(server, *timeout)
	if err != nil {
		if *wazuh {
			_ = report.Emit(report.Event{Tool: "ntp", Target: server, Severity: report.SeverityMedium, Summary: "NTP-сервер недоступен"})
		}
		return err
	}

	offBig := math.Abs(res.OffsetMs) > float64(*maxOffset)/float64(time.Millisecond)
	if *wazuh {
		sev := report.SeverityInfo
		summary := "NTP: смещение в норме"
		if offBig {
			sev = report.SeverityMedium
			summary = fmt.Sprintf("NTP: большое смещение часов %.1f мс", res.OffsetMs)
		}
		_ = report.Emit(report.Event{Tool: "ntp", Target: res.Server, Severity: sev, Summary: summary,
			Data: map[string]any{"offset_ms": res.OffsetMs, "rtt_ms": res.RTTMs, "stratum": res.Stratum}})
	}

	if *asJSON {
		printJSON(res)
		return nil
	}

	fmt.Printf("NTP %s\n", res.Server)
	fmt.Printf("  Время сервера (UTC): %s\n", res.ServerUTC.Format("2006-01-02 15:04:05.000"))
	fmt.Printf("  Stratum:  %d\n", res.Stratum)
	fmt.Printf("  Смещение: %.2f мс%s\n", res.OffsetMs, warnTag(offBig))
	fmt.Printf("  RTT:      %.2f мс\n", res.RTTMs)
	return nil
}

func warnTag(big bool) string {
	if big {
		return "  ⚠ велико"
	}
	return ""
}

func printJSON(res Result) {
	fmt.Printf("{\n  \"server\": %q,\n  \"server_utc\": %q,\n  \"offset_ms\": %.3f,\n  \"rtt_ms\": %.3f,\n  \"stratum\": %d\n}\n",
		res.Server, res.ServerUTC.Format(time.RFC3339Nano), res.OffsetMs, res.RTTMs, res.Stratum)
}
