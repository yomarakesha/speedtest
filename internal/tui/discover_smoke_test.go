package tui

import (
	"strings"
	"testing"

	"speedtest/internal/portscan"

	tea "github.com/charmbracelet/bubbletea"
)

// TestDiscoverMenuRenders checks the mode menu shows every scope option and the
// beginner prompt, so a layout regression is caught without a live terminal.
func TestDiscoverMenuRenders(t *testing.T) {
	tab := newDiscoverTab()
	tab.SetSize(100, 24)
	out := tab.View()
	for _, want := range []string{
		"Что просканировать?",
		"Моя сеть", "Все мои сети", "Выбрать сети вручную", "Найти все сети",
		"Нажмите Enter",
		"ICMP-пинг", "вкл",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("menu missing %q\n%s", want, out)
		}
	}
}

// TestDiscoverICMPToggle checks [i] flips the liveness knob and that the choice
// reaches the scan options rather than only the menu text.
func TestDiscoverICMPToggle(t *testing.T) {
	tb := newDiscoverTab()
	tb.SetSize(100, 24)

	dt, ok := tb.(*discoverTab)
	if !ok {
		t.Fatalf("newDiscoverTab() = %T, want *discoverTab", tb)
	}
	if dt.noICMP {
		t.Error("ICMP probing should default to on")
	}

	tb, _ = tb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	dt = tb.(*discoverTab)
	if !dt.noICMP {
		t.Fatal("pressing [i] did not turn ICMP off")
	}
	if out := tb.View(); !strings.Contains(out, "выкл") {
		t.Errorf("menu does not show the ICMP knob as off\n%s", out)
	}

	tb, _ = tb.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	if tb.(*discoverTab).noICMP {
		t.Error("pressing [i] twice did not turn ICMP back on")
	}
}

// TestDiscoverResultsShowMAC covers the ARP-only case: a device with no open
// port and no hostname must still be listed, identified by its MAC.
func TestDiscoverResultsShowMAC(t *testing.T) {
	dt := newDiscoverTab().(*discoverTab)
	dt.SetSize(120, 24)
	dt.done = true
	dt.hosts = []portscan.HostResult{{IP: "192.168.1.7", MAC: "00:11:22:33:44:55"}}
	dt.refreshRows()

	out := dt.View()
	for _, want := range []string{"MAC", "192.168.1.7", "00:11:22:33:44:55"} {
		if !strings.Contains(out, want) {
			t.Errorf("results view missing %q\n%s", want, out)
		}
	}
}
