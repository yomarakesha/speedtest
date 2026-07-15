package bwmon

import (
	"encoding/csv"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// --- Windows (Get-NetAdapterStatistics) ------------------------------------

// sampleWindows reads per-adapter byte counters via PowerShell. Output encoding
// is forced to UTF-8 so localized adapter names come through intact; the
// counters themselves are locale-independent integers.
func sampleWindows() ([]NICSample, error) {
	const ps = `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ` +
		`Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Csv -NoTypeInformation`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).Output()
	if err != nil {
		return nil, ErrNoCounters
	}
	return parseNetAdapterCSV(string(out))
}

// parseNetAdapterCSV parses the "Name,ReceivedBytes,SentBytes" CSV emitted by
// Get-NetAdapterStatistics into samples.
func parseNetAdapterCSV(text string) ([]NICSample, error) {
	r := csv.NewReader(strings.NewReader(strings.TrimSpace(text)))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []NICSample
	for i, rec := range records {
		if i == 0 || len(rec) < 3 { // header or short row
			continue
		}
		rx, err1 := strconv.ParseUint(strings.TrimSpace(rec[1]), 10, 64)
		tx, err2 := strconv.ParseUint(strings.TrimSpace(rec[2]), 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, NICSample{Name: rec[0], Rx: rx, Tx: tx})
	}
	return out, nil
}

// --- Linux (/proc/net/dev) -------------------------------------------------

func sampleLinux() ([]NICSample, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, ErrNoCounters
	}
	return parseProcNetDev(string(data)), nil
}

// parseProcNetDev parses /proc/net/dev. Each data line is
// "iface: rxBytes rxPackets ... txBytes txPackets ...": field 0 (after the
// colon) is rx bytes, field 8 is tx bytes.
func parseProcNetDev(text string) []NICSample {
	var out []NICSample
	for line := range strings.SplitSeq(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // header lines have no colon
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 9 || name == "lo" {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, NICSample{Name: name, Rx: rx, Tx: tx})
	}
	return out
}
