// Package wifi surveys the local wireless environment: the current association
// (SSID, signal, channel) and nearby access points, plus simple 2.4 GHz channel
// advice. It shells out to the OS wireless tool (netsh / nmcli / airport) and
// parses the output by value patterns rather than localized field labels, so it
// works regardless of the console language.
//
// It deliberately does NOT attempt per-client traffic accounting: seeing other
// stations' throughput requires a monitor-mode adapter (or being the AP), which
// is out of scope here.
package wifi

import (
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// ErrNoWiFi is returned when no wireless interface or scan result is available.
var ErrNoWiFi = errors.New("беспроводной интерфейс не найден (нет Wi-Fi или адаптер выключен)")

// Link describes the current wireless association.
type Link struct {
	Connected bool   `json:"connected"`
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Security  string `json:"security,omitempty"`
	Radio     string `json:"radio,omitempty"`
	Band      string `json:"band,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	SignalPct int    `json:"signal_pct"`
}

// AP describes one nearby access point (one BSSID).
type AP struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Security  string `json:"security,omitempty"`
	Radio     string `json:"radio,omitempty"`
	Band      string `json:"band,omitempty"`
	Channel   int    `json:"channel"`
	SignalPct int    `json:"signal_pct"`
}

// Survey returns the current link and the list of nearby APs.
func Survey() (Link, []AP, error) {
	switch runtime.GOOS {
	case "windows":
		return surveyWindows()
	case "linux":
		return surveyLinux()
	default:
		return Link{}, nil, ErrNoWiFi
	}
}

var (
	signalRe = regexp.MustCompile(`^(\d{1,3})\s*%$`)
	radioRe  = regexp.MustCompile(`802\.11`)
	macRe    = regexp.MustCompile(`^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$`)
)

// bandForChannel maps a Wi-Fi channel number to a human band label.
func bandForChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4 ГГц"
	case ch >= 32 && ch <= 196:
		return "5 ГГц"
	default:
		return ""
	}
}

// securityLabel normalizes a value that looks like an auth/encryption setting,
// or returns "" if the value is not recognizable as one (locale-independent:
// keyed off the value, not the localized field label).
func securityLabel(v string) string {
	u := strings.ToUpper(v)
	switch {
	case strings.Contains(u, "WPA3"):
		return "WPA3"
	case strings.Contains(u, "WPA2"), strings.Contains(u, "RSNA"):
		return "WPA2"
	case strings.Contains(u, "WPA"):
		return "WPA"
	case strings.Contains(u, "WEP"):
		return "WEP"
	case u == "OPEN" || strings.HasPrefix(u, "ОТКР"):
		return "Open"
	default:
		return ""
	}
}

// splitKV splits a "key : value" line on the first colon, trimming both sides.
func splitKV(line string) (key, val string, ok bool) {
	k, v, found := strings.Cut(line, ":")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// pureInt returns n>0 if s is a plain integer in the plausible channel range.
func pureInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 233 {
		return 0
	}
	return n
}

// ChannelAdvice inspects 2.4 GHz APs and recommends the least-congested of the
// non-overlapping channels 1/6/11. Returns "" if there is nothing to advise.
func ChannelAdvice(aps []AP) string {
	load := map[int]int{1: 0, 6: 0, 11: 0}
	any := false
	for _, ap := range aps {
		if ap.Channel < 1 || ap.Channel > 14 {
			continue
		}
		any = true
		// Each AP mainly interferes with the nearest of 1/6/11.
		best, bd := 1, 99
		for _, c := range []int{1, 6, 11} {
			if d := abs(ap.Channel - c); d < bd {
				best, bd = c, d
			}
		}
		load[best]++
	}
	if !any {
		return ""
	}
	best, bn := 1, load[1]
	for _, c := range []int{6, 11} {
		if load[c] < bn {
			best, bn = c, load[c]
		}
	}
	return "Наименее загруженный канал 2.4 ГГц: " + strconv.Itoa(best) +
		" (загрузка 1/6/11: " + strconv.Itoa(load[1]) + "/" + strconv.Itoa(load[6]) + "/" + strconv.Itoa(load[11]) + ")"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// sortAPs orders APs by signal strength descending, then SSID, for stable UI.
func sortAPs(aps []AP) {
	sort.Slice(aps, func(i, j int) bool {
		if aps[i].SignalPct != aps[j].SignalPct {
			return aps[i].SignalPct > aps[j].SignalPct
		}
		return aps[i].SSID < aps[j].SSID
	})
}

// runCmd runs a command and returns its stdout as a string.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}
