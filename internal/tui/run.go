package tui

import tea "github.com/charmbracelet/bubbletea"

// Run launches the full-screen dashboard and blocks until the user quits.
func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}
