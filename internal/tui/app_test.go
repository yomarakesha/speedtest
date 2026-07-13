package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestModelRendersEveryTab exercises the whole render path headlessly: size the
// model, switch to each tab, and render. This catches nil-panics in View/SetSize
// without needing a real terminal.
func TestModelRendersEveryTab(t *testing.T) {
	var m tea.Model = New()
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})

	n := len(New().tabs)
	for i := range n {
		key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune('1' + i)}}
		m, _ = m.Update(key)
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
	disc, ok := rm.tabs[5].(*discoverTab) // Обзор
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
