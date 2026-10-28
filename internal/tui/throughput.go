package tui

import (
	"fmt"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// meter is the shared throughput widget behind the Интернет, Локалка and HTTP
// tabs. It owns the spinner, one or two live sparklines, running peak/current
// state, and renders a current-vs-peak gauge under each graph. Each tab embeds
// a meter and only supplies its own engine call, phase labels and history record
// — the sampling/rendering mechanics live here once.
type meter struct {
	sty  styles
	spin spinner.Model
	dual bool // true = two directions (download + upload)

	dn, up  sparkline.Model
	w, h    int
	reserve int // rows the tab's header/status consume above the charts

	curDn, peakDn float64
	curUp, peakUp float64
}

// newMeter builds a meter. dual controls whether an upload graph exists.
func newMeter(sty styles, dual bool) meter {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sty.accent
	m := meter{sty: sty, spin: sp, dual: dual}
	m.dn = sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(sty.good))
	if dual {
		m.up = sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(sty.accent))
	}
	return m
}

// setSize records the layout budget and resizes the sparklines.
func (m *meter) setSize(w, h, reserve int) {
	m.w, m.h, m.reserve = w, h, reserve
	cw, ch := m.chartSize()
	m.dn.Resize(cw, ch)
	if m.dual {
		m.up.Resize(cw, ch)
	}
}

// chartSize is the per-graph width/height inside the frame. Two graphs share the
// width when dual; a single graph gets it all.
func (m *meter) chartSize() (int, int) {
	cw := m.w - 6
	if m.dual {
		cw = (m.w - 10) / 2
	}
	cw = max(cw, 10)
	ch := max(m.h-m.reserve, 3)
	return cw, ch
}

// reset clears the graphs and stats for a new run, rebuilding them at the
// current size so the first samples land on a correctly-scaled canvas.
func (m *meter) reset() {
	cw, ch := m.chartSize()
	m.dn = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(m.sty.good))
	if m.dual {
		m.up = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(m.sty.accent))
	}
	m.curDn, m.peakDn, m.curUp, m.peakUp = 0, 0, 0, 0
}

func (m *meter) pushDown(v float64) {
	m.curDn = v
	m.peakDn = max(m.peakDn, v)
	pushScaledSpark(&m.dn, v, m.peakDn)
}

func (m *meter) pushUp(v float64) {
	m.curUp = v
	m.peakUp = max(m.peakUp, v)
	pushScaledSpark(&m.up, v, m.peakUp)
}

// tick advances the spinner; call from the tab's spinner.TickMsg case.
func (m *meter) tick(msg spinner.TickMsg) tea.Cmd {
	var cmd tea.Cmd
	m.spin, cmd = m.spin.Update(msg)
	return cmd
}

// gauge renders a labelled current-vs-peak bar for one direction.
func (m *meter) gauge(cur, peak float64, fill lipgloss.Style) string {
	frac := 0.0
	if peak > 0 {
		frac = cur / peak
	}
	cw, _ := m.chartSize()
	bw := max(cw-14, 6)
	return bar(frac, bw, fill, m.sty.muted) + " " + m.sty.big.Render(fmtMbps(cur))
}

// charts renders the graph(s) with the given direction labels plus gauges.
func (m *meter) charts(dnLabel, upLabel string) string {
	dn := lipgloss.JoinVertical(lipgloss.Left,
		m.sty.good.Render(dnLabel),
		m.dn.View(),
		m.gauge(m.curDn, m.peakDn, m.sty.good),
	)
	if !m.dual {
		return dn
	}
	up := lipgloss.JoinVertical(lipgloss.Left,
		m.sty.accent.Render(upLabel),
		m.up.View(),
		m.gauge(m.curUp, m.peakUp, m.sty.accent),
	)
	return lipgloss.JoinHorizontal(lipgloss.Top, dn, "    ", up)
}

// peakLabel is a small helper for phase lines that want the download peak.
func (m *meter) peakDnStr() string { return fmt.Sprintf("пик %s", fmtMbps(m.peakDn)) }
