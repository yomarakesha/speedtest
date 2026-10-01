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
		out := m.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("tab %d rendered empty", i+1)
		}
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	}
}

// TestDigitShortcuts verifies 1-9 and 0 jump directly to the matching tab.
// Each case starts from a fresh model (a tab with a focused text input
// swallows further digit keys as typed text rather than navigation, so
// shortcuts can only be verified one at a time from the default state).
func TestDigitShortcuts(t *testing.T) {
	want := New().tabs
	for i := range want {
		if i >= 10 {
			break // beyond 1-9,0 only Tab/Shift+Tab reach further tabs
		}
		key := rune('1' + i)
		if i == 9 {
			key = '0'
		}

		m2, _ := New().Update(tea.WindowSizeMsg{Width: 100, Height: 30})
		mm := m2.(model)
		next, _ := mm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
		mm = next.(model)
		if got := mm.tabs[mm.active].Title(); got != want[i].Title() {
			t.Fatalf("key %q: active tab = %q, want %q", string(key), got, want[i].Title())
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
