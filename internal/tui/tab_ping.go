package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/config"
	"speedtest/internal/history"
	"speedtest/internal/ping"

	"github.com/NimbleMarkets/ntcharts/canvas/runes"
	"github.com/NimbleMarkets/ntcharts/linechart/streamlinechart"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// pingSampleMsg carries one probe result from the engine goroutine. ch
// identifies the run it belongs to: every non-key message is broadcast to all
// tabs, and a stopped or superseded run can still have buffered samples in
// flight, so the handler ignores samples whose channel isn't the current run's.
type pingSampleMsg struct {
	ch chan tea.Msg
	s  ping.Sample
}

// pingTab is the gping-style live latency screen: a host input on top and a
// scrolling RTT chart below with min/avg/max/loss stats.
type pingTab struct {
	st    styles
	input textinput.Model
	chart streamlinechart.Model
	w, h  int

	running bool
	host    string
	cancel  context.CancelFunc
	ch      chan tea.Msg

	sent, recv int
	last       float64
	min, max   float64
	sum        float64
	chartMax   float64
}

func newPingTab(seed string) tab {
	ti := textinput.New()
	ti.Placeholder = "8.8.8.8 или host:port"
	ti.CharLimit = 253
	ti.Prompt = "Хост: "
	ti.SetValue(seed)
	ti.Focus()
	t := &pingTab{st: newStyles(), input: ti, chartMax: 50}
	t.newChart()
	return t
}

func (t *pingTab) Title() string { return "Пинг" }
func (t *pingTab) Init() tea.Cmd { return textinput.Blink }
func (t *pingTab) Busy() bool    { return t.running }

func (t *pingTab) ShortHelp() []string {
	return []string{"[Enter] старт/стоп", "[Esc] сброс", "ввод хоста активен"}
}

func (t *pingTab) Capturing() bool { return t.input.Focused() }

func (t *pingTab) SetSize(w, h int) {
	t.w, t.h = w, h
	cw, ch := t.chartSize()
	t.chart.Resize(cw, ch)
	t.redraw()
}

// chartSize returns the chart dimensions inside the frame: frame border+padding
// eats 4 columns and 2 rows; input + stats lines eat 4 more rows.
func (t *pingTab) chartSize() (int, int) {
	return max(t.w-6, 10), max(t.h-8, 4)
}

// newChart builds a fresh chart sized for the current max RTT scale.
func (t *pingTab) newChart() {
	cw, ch := t.chartSize()
	c := streamlinechart.New(cw, ch)
	c.AxisStyle = t.st.muted
	c.LabelStyle = t.st.muted
	c.SetYRange(0, t.chartMax)
	c.SetViewYRange(0, t.chartMax)
	c.SetStyles(runes.ThinLineStyle, t.st.accent)
	c.DrawXYAxisAndLabel()
	t.chart = c
}

func (t *pingTab) redraw() {
	t.chart.Clear()
	t.chart.DrawXYAxisAndLabel()
	t.chart.Draw()
}

// start launches the probe goroutine bridging ping.Sample onto t.ch.
func (t *pingTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	config.Remember("ping", host)
	t.host = ping.NormalizeHost(host, ping.DefaultPort)
	t.sent, t.recv, t.sum, t.last = 0, 0, 0, 0
	t.min, t.max = 0, 0
	t.chartMax = 50
	t.newChart()

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 16)
	t.ch = ch
	t.running = true
	t.input.Blur()

	go func() {
		for s := range ping.Probe(ctx, ping.Options{
			Host:     t.host,
			Count:    0, // до остановки
			Timeout:  pingTimeout,
			Interval: pingInterval,
		}) {
			ch <- pingSampleMsg{ch: ch, s: s}
		}
		ch <- engineDoneMsg{ch: ch}
	}()
	return listen(ch)
}

func (t *pingTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
	t.input.Focus()
	if t.sent > 0 {
		avg := 0.0
		if t.recv > 0 {
			avg = t.sum / float64(t.recv)
		}
		loss := float64(t.sent-t.recv) / float64(t.sent) * 100
		_ = history.Append(history.Record{
			Kind:    history.KindPing,
			Target:  t.host,
			PingMs:  avg,
			LossPct: loss,
		})
	}
}

func (t *pingTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if t.running {
				t.stop()
				return t, nil
			}
			return t, t.start()
		case "esc":
			t.stop()
			t.input.SetValue("")
			return t, nil
		}

	case pingSampleMsg:
		// Ignore samples from a stopped or superseded run (see pingSampleMsg).
		if !t.running || msg.ch != t.ch {
			return t, nil
		}
		s := msg.s
		t.sent++
		if s.OK() {
			t.recv++
			t.last = s.RTTMs
			t.sum += s.RTTMs
			if t.min == 0 || s.RTTMs < t.min {
				t.min = s.RTTMs
			}
			if s.RTTMs > t.max {
				t.max = s.RTTMs
			}
			// Rescale the Y axis when a sample overflows the current range.
			if s.RTTMs > t.chartMax {
				t.chartMax = s.RTTMs * 1.5
				t.chart.SetYRange(0, t.chartMax)
				t.chart.SetViewYRange(0, t.chartMax)
			}
			t.chart.Push(s.RTTMs)
		} else {
			t.chart.Push(0) // потеря — провал до нуля
		}
		t.redraw()
		return t, listen(t.ch)

	case engineDoneMsg:
		return t, nil
	}

	if !t.running {
		var cmd tea.Cmd
		t.input, cmd = t.input.Update(msg)
		return t, cmd
	}
	return t, nil
}

func (t *pingTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	if t.running || t.sent > 0 {
		b.WriteString(t.statsLine())
	} else if hint := hostHint(t.st, t.input.Value()); hint != "" {
		b.WriteString(hint)
	} else {
		b.WriteString(t.st.muted.Render("Введите хост и нажмите Enter — график задержки в реальном времени."))
	}
	b.WriteString("\n")
	b.WriteString(t.chart.View())

	title := "Живой пинг (TCP)"
	if t.host != "" {
		title += "  ·  " + t.host
	}
	body := b.String()
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.st.frame(title, t.w, t.h, body))
}

func (t *pingTab) statsLine() string {
	loss := 0.0
	if t.sent > 0 {
		loss = float64(t.sent-t.recv) / float64(t.sent) * 100
	}
	avg := 0.0
	if t.recv > 0 {
		avg = t.sum / float64(t.recv)
	}
	lossStyle := t.st.good
	if loss > 0 {
		lossStyle = t.st.warn
	}
	if loss >= 50 {
		lossStyle = t.st.bad
	}
	state := t.st.good.Render("● идёт")
	if !t.running {
		state = t.st.muted.Render("■ стоп")
	}
	return fmt.Sprintf("%s   тек %s   мин %s   сред %s   макс %s   потери %s   (%d/%d)",
		state,
		rttStyle(t.st, t.last).Bold(true).Render(fmt.Sprintf("%.1f мс", t.last)),
		rttStyle(t.st, t.min).Render(fmt.Sprintf("%.1f", t.min)),
		rttStyle(t.st, avg).Render(fmt.Sprintf("%.1f", avg)),
		rttStyle(t.st, t.max).Render(fmt.Sprintf("%.1f", t.max)),
		lossStyle.Render(fmt.Sprintf("%.0f%%", loss)),
		t.recv, t.sent)
}

// rttStyle colors a latency value by band: good < 50 мс, warn < 150 мс, else bad.
func rttStyle(s styles, ms float64) lipgloss.Style {
	switch {
	case ms <= 0:
		return s.muted
	case ms < 50:
		return s.good
	case ms < 150:
		return s.warn
	default:
		return s.bad
	}
}
