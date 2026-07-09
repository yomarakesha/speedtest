package tui

import (
	"fmt"
	"strings"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// listen returns a command that blocks for the next message on ch. Engine tabs
// launch a goroutine that pushes messages onto ch and re-issue listen after
// each one, turning a Go channel into a stream of tea.Msg.
func listen(ch chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// engineDoneMsg signals an engine goroutine finished (err nil on success).
type engineDoneMsg struct{ err error }

// fmtMbps renders a throughput value with a sensible unit.
func fmtMbps(v float64) string {
	if v >= 1000 {
		return fmt.Sprintf("%.2f Гбит/с", v/1000)
	}
	return fmt.Sprintf("%.1f Мбит/с", v)
}

// bar draws a horizontal meter of the given width for frac in [0,1].
func bar(frac float64, width int, fill, empty lipgloss.Style) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	n := int(frac*float64(width) + 0.5)
	if n > width {
		n = width
	}
	return fill.Render(strings.Repeat("█", n)) + empty.Render(strings.Repeat("░", width-n))
}

// pushScaledSpark pushes v onto a sparkline and grows its max scale when the
// running peak exceeds it, so the graph never clips.
func pushScaledSpark(sl *sparkline.Model, v, peak float64) {
	if peak > sl.MaxValue() {
		sl.SetMax(peak * 1.2)
	}
	sl.Push(v)
	sl.Draw()
}

// panel wraps body in a rounded, titled box sized to (w,h). It is the standard
// content frame for every tab.
func (s styles) frame(title string, w, h int, body string) string {
	inner := w - 2 // border
	if inner < 1 {
		inner = 1
	}
	head := s.panelTtl.Render(title)
	content := lipgloss.JoinVertical(lipgloss.Left, head, body)
	return s.panel.Width(inner).Height(h - 2).Render(content)
}
