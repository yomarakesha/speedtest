package tui

import tea "github.com/charmbracelet/bubbletea"

// Run launches the full-screen dashboard and blocks until the user quits.
//
// Mouse capture is intentionally NOT enabled: the dashboard is fully
// keyboard-driven, and grabbing mouse events would break the terminal's own
// text selection / copy while the TUI is running.
func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
