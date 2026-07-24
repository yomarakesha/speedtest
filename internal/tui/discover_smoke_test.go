package tui

import (
	"strings"
	"testing"
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
	} {
		if !strings.Contains(out, want) {
			t.Errorf("menu missing %q\n%s", want, out)
		}
	}
}
