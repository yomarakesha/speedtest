package wifi

import "strings"

// --- Windows (netsh) -------------------------------------------------------

func surveyWindows() (Link, []AP, error) {
	ifOut, err := runCmd("netsh", "wlan", "show", "interfaces")
	if err != nil {
		return Link{}, nil, ErrNoWiFi
	}
	link := parseNetshInterface(ifOut)

	netOut, _ := runCmd("netsh", "wlan", "show", "networks", "mode=bssid")
	aps := parseNetshNetworks(netOut)
	sortAPs(aps)

	// Fill the current link's channel/band/radio from the matching AP, since
	// those labels are localized in `show interfaces` but the BSSID is not.
	if link.BSSID != "" {
		for _, ap := range aps {
			if strings.EqualFold(ap.BSSID, link.BSSID) {
				link.Channel, link.Band = ap.Channel, ap.Band
				if link.Radio == "" {
					link.Radio = ap.Radio
				}
				break
			}
		}
	}

	if !link.Connected && len(aps) == 0 {
		return link, aps, ErrNoWiFi
	}
	return link, aps, nil
}

// parseNetshInterface extracts the current association from
// `netsh wlan show interfaces`. It keys off ASCII-only labels (SSID/BSSID) and
// value patterns (percent = signal), so it survives console localization.
func parseNetshInterface(text string) Link {
	var l Link
	for line := range strings.SplitSeq(text, "\n") {
		key, val, ok := splitKV(line)
		if !ok || val == "" {
			continue
		}
		switch {
		case strings.EqualFold(key, "SSID"):
			l.SSID, l.Connected = val, true
		case strings.Contains(strings.ToUpper(key), "BSSID") && macRe.MatchString(val):
			// Label varies by driver/locale: "BSSID", "AP BSSID", etc.
			l.BSSID = normMAC(val)
		case signalRe.MatchString(val):
			if m := signalRe.FindStringSubmatch(val); m != nil {
				l.SignalPct = pureInt(m[1])
			}
		case radioRe.MatchString(val) && l.Radio == "":
			l.Radio = val
		default:
			if s := securityLabel(val); s != "" && l.Security == "" {
				l.Security = s
			}
		}
	}
	return l
}

// parseNetshNetworks extracts nearby APs from
// `netsh wlan show networks mode=bssid`. Structure is locale-independent:
// "SSID N" opens a network block, "BSSID N" opens an AP, and within it the
// percent value is signal, a bare small integer is the channel, and an
// 802.11* value is the radio type.
func parseNetshNetworks(text string) []AP {
	var aps []AP
	var curSSID, curSec string
	var cur *AP // points into aps

	flush := func() { cur = nil }

	for line := range strings.SplitSeq(text, "\n") {
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToUpper(key), "SSID ") && !strings.HasPrefix(strings.ToUpper(key), "BSSID"):
			curSSID, curSec = val, ""
			flush()
		case strings.HasPrefix(strings.ToUpper(key), "BSSID "):
			aps = append(aps, AP{SSID: curSSID, BSSID: normMAC(val), Security: curSec})
			cur = &aps[len(aps)-1]
		case signalRe.MatchString(val):
			if cur != nil {
				if m := signalRe.FindStringSubmatch(val); m != nil {
					cur.SignalPct = pureInt(m[1])
				}
			}
		case radioRe.MatchString(val):
			if cur != nil {
				cur.Radio = val
			}
		case pureInt(val) > 0:
			if cur != nil && cur.Channel == 0 {
				cur.Channel = pureInt(val)
				cur.Band = bandForChannel(cur.Channel)
			}
		default:
			if s := securityLabel(val); s != "" {
				if cur != nil {
					cur.Security = s
				} else {
					curSec = s // network-level auth, before the first BSSID
				}
			}
		}
	}
	return aps
}

// --- Linux (nmcli) ---------------------------------------------------------

func surveyLinux() (Link, []AP, error) {
	out, err := runCmd("nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,CHAN,SECURITY,BSSID", "dev", "wifi")
	if err != nil {
		return Link{}, nil, ErrNoWiFi
	}
	link, aps := parseNmcli(out)
	sortAPs(aps)
	if !link.Connected && len(aps) == 0 {
		return link, aps, ErrNoWiFi
	}
	return link, aps, nil
}

// parseNmcli parses terse `nmcli -t -f ACTIVE,SSID,SIGNAL,CHAN,SECURITY,BSSID
// dev wifi` output. Fields are colon-separated; literal colons inside the BSSID
// are backslash-escaped by nmcli, so we split on unescaped colons.
func parseNmcli(text string) (Link, []AP) {
	var link Link
	var aps []AP
	for line := range strings.SplitSeq(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := splitEscaped(line)
		if len(f) < 6 {
			continue
		}
		active := strings.EqualFold(f[0], "yes")
		ap := AP{
			SSID:      f[1],
			SignalPct: pureInt(f[2]),
			Channel:   pureInt(f[3]),
			Security:  securityLabel(f[4]),
			BSSID:     normMAC(f[5]),
		}
		ap.Band = bandForChannel(ap.Channel)
		if ap.Security == "" && f[4] != "" && f[4] != "--" {
			ap.Security = f[4]
		}
		aps = append(aps, ap)
		if active {
			link = Link{
				Connected: true, SSID: ap.SSID, BSSID: ap.BSSID,
				Security: ap.Security, Band: ap.Band,
				Channel: ap.Channel, SignalPct: ap.SignalPct,
			}
		}
	}
	return link, aps
}

// splitEscaped splits an nmcli terse line on unescaped ':' and unescapes '\:'.
func splitEscaped(line string) []string {
	var fields []string
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			b.WriteByte(line[i+1])
			i++
			continue
		}
		if c == ':' {
			fields = append(fields, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	fields = append(fields, b.String())
	return fields
}

// normMAC lowercases a MAC and normalizes separators to ':'.
func normMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", ":")
	return s
}
