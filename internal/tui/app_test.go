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
	for i := 0; i < n; i++ {
		key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune('1' + i)}}
		m, _ = m.Update(key)
		out := m.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("tab %d rendered empty", i+1)
		}
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
