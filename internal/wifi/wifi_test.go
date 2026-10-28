package wifi

import (
	"strings"
	"testing"
)

const netshInterfaceEN = `
    Name                   : Wi-Fi
    Description            : Intel Wireless
    SSID                   : MyNetwork
    BSSID                  : 00-11-22-33-44-55
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Signal                 : 78%
    Receive rate (Mbps)    : 300
`

const netshInterfaceRU = `
    Имя                    : Wi-Fi
    Описание               : Intel Wireless
    SSID                   : MyNetwork
    AP BSSID               : 00-11-22-33-44-55
    Тип радио              : 802.11ac
    Проверка подлинности   : WPA2-Personal
    Сигнал                 : 78%
`

func TestParseNetshInterface(t *testing.T) {
	for name, text := range map[string]string{"EN": netshInterfaceEN, "RU": netshInterfaceRU} {
		l := parseNetshInterface(text)
		if !l.Connected {
			t.Errorf("%s: not marked connected", name)
		}
		if l.SSID != "MyNetwork" {
			t.Errorf("%s: SSID = %q", name, l.SSID)
		}
		if l.BSSID != "00:11:22:33:44:55" {
			t.Errorf("%s: BSSID = %q", name, l.BSSID)
		}
		if l.SignalPct != 78 {
			t.Errorf("%s: Signal = %d", name, l.SignalPct)
		}
		if l.Security != "WPA2" {
			t.Errorf("%s: Security = %q", name, l.Security)
		}
		if l.Radio != "802.11ac" {
			t.Errorf("%s: Radio = %q", name, l.Radio)
		}
	}
}

const netshNetworks = `
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : MyNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 80%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : 66:77:88:99:aa:bb
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : cc:dd:ee:ff:00:11
         Signal             : 55%
         Channel            : 11
`

func TestParseNetshNetworks(t *testing.T) {
	aps := parseNetshNetworks(netshNetworks)
	if len(aps) != 3 {
		t.Fatalf("got %d APs, want 3: %+v", len(aps), aps)
	}
	// aps[0]: MyNetwork on 5 GHz ch36
	if aps[0].BSSID != "00:11:22:33:44:55" || aps[0].Channel != 36 || aps[0].Band != "5 ГГц" {
		t.Errorf("ap0 = %+v", aps[0])
	}
	if aps[0].SignalPct != 80 || aps[0].Security != "WPA2" || aps[0].Radio != "802.11ac" {
		t.Errorf("ap0 fields = %+v", aps[0])
	}
	// aps[1]: same SSID, 2.4 GHz ch6
	if aps[1].SSID != "MyNetwork" || aps[1].Channel != 6 || aps[1].Band != "2.4 ГГц" {
		t.Errorf("ap1 = %+v", aps[1])
	}
	// aps[2]: hidden SSID, Open, ch11
	if aps[2].SSID != "" || aps[2].Security != "Open" || aps[2].Channel != 11 {
		t.Errorf("ap2 = %+v", aps[2])
	}
}

func TestParseNmcli(t *testing.T) {
	const out = `yes:MyNetwork:78:36:WPA2:00\:11\:22\:33\:44\:55
no:Neighbor:45:6:WPA1 WPA2:66\:77\:88\:99\:AA\:BB
no::30:11:--:CC\:DD\:EE\:FF\:00\:11`
	link, aps := parseNmcli(out)
	if !link.Connected || link.SSID != "MyNetwork" || link.Channel != 36 || link.SignalPct != 78 {
		t.Errorf("link = %+v", link)
	}
	if len(aps) != 3 {
		t.Fatalf("got %d APs, want 3", len(aps))
	}
	if aps[0].BSSID != "00:11:22:33:44:55" {
		t.Errorf("ap0 BSSID = %q", aps[0].BSSID)
	}
	if aps[2].SSID != "" || aps[2].Security != "" {
		t.Errorf("hidden ap2 = %+v", aps[2])
	}
}

func TestChannelAdvice(t *testing.T) {
	aps := []AP{
		{Channel: 6}, {Channel: 6}, {Channel: 11}, {Channel: 36}, // 36 is 5GHz, ignored
	}
	got := ChannelAdvice(aps)
	if got == "" {
		t.Fatal("expected advice, got empty")
	}
	// channel 1 has zero load, should be recommended
	if !strings.Contains(got, "ГГц: 1") {
		t.Errorf("advice = %q, want it to recommend channel 1", got)
	}
	// No 2.4 GHz APs => no advice.
	if a := ChannelAdvice([]AP{{Channel: 36}}); a != "" {
		t.Errorf("expected no advice for 5GHz-only, got %q", a)
	}
}
