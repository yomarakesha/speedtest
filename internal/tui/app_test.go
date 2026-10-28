package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TestModelRendersEveryTab exercises the whole render path headlessly: size the
// model, switch to each tab, and render. This catches nil-panics in View/SetSize
// without needing a real terminal.
func TestModelRendersEveryTab(t *testing.T) {
	var m tea.Model = New()
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	n := len(New().tabs)
	for i := range n {
		if i > 0 {
			m, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
		}
		if got := m.(model).active; got != i {
			t.Fatalf("after %d Tab presses active = %d", i, got)
		}
		out := m.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("tab %d rendered empty", i+1)
		}
	}
}

// TestBackgroundBroadcast verifies engine messages reach their owning tab even
// when a different tab is active — the mechanism that keeps measurements running
// in the background.
func TestBackgroundBroadcast(t *testing.T) {
	root := New()
	var m tea.Model = root
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	// Active tab stays index 0 (internet); deliver a discover-engine message.
	m, _ = m.Update(discPhaseMsg{phase: "scan", done: 3, total: 10})

	rm := m.(model)
	disc, ok := rm.tabs[5].(*discoverTab) // Скан сети
	if !ok {
		t.Fatalf("tab 5 is %T, expected *discoverTab", rm.tabs[5])
	}
	if disc.pdone != 3 || disc.ptotal != 10 {
		t.Errorf("discover tab did not receive background message: pdone=%d ptotal=%d",
			disc.pdone, disc.ptotal)
	}
}

// TestHelpOverlayToggles verifies "?" flips the help overlay on and off.
func TestHelpOverlayToggles(t *testing.T) {
	var m tea.Model = New()
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !strings.Contains(m.View(), "Справка") {
		t.Error("help overlay did not open on '?'")
	}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if strings.Contains(m.View(), "Навигация") {
		t.Error("help overlay did not close on second '?'")
	}
}

// TestDigitKeysJump checks 1-9 select tabs 1-9 and 0 selects the 10th. The
// order matters: a tab with a focused text field keeps digits for itself, so
// the sequence only passes through tabs without one.
func TestDigitKeysJump(t *testing.T) {
	var m tea.Model = New()
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	for _, c := range []struct {
		key  rune
		want int
	}{{'1', 0}, {'7', 6}, {'9', 8}, {'0', 9}} {
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{c.key}})
		if got := m.(model).active; got != c.want {
			t.Errorf("key %q: active = %d, want %d", c.key, got, c.want)
		}
	}
}

// TestTabBarFitsWidth checks the tab bar never exceeds the terminal width and
// always shows the active tab, even with more tabs than fit on one line.
func TestTabBarFitsWidth(t *testing.T) {
	m := New()
	m.width, m.height = 80, 30
	for i := range m.tabs {
		m.active = i
		bar := m.tabBar()
		if w := lipgloss.Width(bar); w > m.width {
			t.Fatalf("tab %d: bar width %d > %d", i, w, m.width)
		}
		if !strings.Contains(bar, m.tabs[i].Title()) {
			t.Errorf("tab %d (%s) not visible in bar", i, m.tabs[i].Title())
		}
	}
}
