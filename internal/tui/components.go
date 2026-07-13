package tui

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// newTable builds a focused, scrollable bubbles/table styled from the palette.
// Used by the discover and history tabs so large result sets scroll (↑/↓) inside
// a fixed viewport instead of overflowing the frame.
func newTable(cols []table.Column, height int) table.Model {
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(true),
		table.WithHeight(max(height, 3)),
	)
	st := table.DefaultStyles()
	st.Header = st.Header.
		Foreground(palette.Muted).Bold(true).
		BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).
		BorderForeground(palette.BorderDim)
	st.Cell = st.Cell.Foreground(palette.Text)
	st.Selected = st.Selected.
		Foreground(lipgloss.Color("#FFFFFF")).Background(palette.Accent).Bold(false)
	t.SetStyles(st)
	return t
}

// hostHint returns a red warning string when v is a non-empty, clearly invalid
// host[:port], or "" when it is empty or plausibly valid. Used under the input
// fields of the ping/lan/scan/trace tabs for immediate feedback.
func hostHint(s styles, v string) string {
	v = strings.TrimSpace(v)
	if v == "" || validHostPort(v) {
		return ""
	}
	return s.bad.Render("⚠ похоже на неверный адрес")
}

// urlHint is hostHint's equivalent for the HTTP tab's URL field.
func urlHint(s styles, v string) string {
	v = strings.TrimSpace(v)
	if v == "" || validURL(v) {
		return ""
	}
	return s.bad.Render("⚠ похоже на неверный URL")
}

// validHostPort accepts "host", "host:port", or "ip[:port]". The port, when
// present, must be 1..65535; an IP-looking host must parse as an IP. Hostnames
// are accepted leniently (no spaces).
func validHostPort(v string) bool {
	host := v
	if h, p, err := net.SplitHostPort(v); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	if host == "" || strings.ContainsAny(host, " \t") {
		return false
	}
	// If it looks like an IPv4 (all dotted digits), require a valid IP.
	if strings.IndexFunc(host, func(r rune) bool {
		return r != '.' && (r < '0' || r > '9')
	}) == -1 {
		return net.ParseIP(host) != nil
	}
	return true // treat as a hostname
}

// validURL accepts a bare host (http:// is assumed) or a full http(s) URL.
func validURL(v string) bool {
	if !strings.Contains(v, "://") {
		return validHostPort(v)
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

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
	frac = min(max(frac, 0), 1)
	n := min(int(frac*float64(width)+0.5), width)
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
	inner := max(w-2, 1) // border
	head := s.panelTTL.Render(title)
	content := lipgloss.JoinVertical(lipgloss.Left, head, body)
	return s.panel.Width(inner).Height(h - 2).Render(content)
}
