package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/trace"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// traceHopsMsg carries a fresh hop-table snapshot from the engine.
type traceHopsMsg struct{ hops []trace.Hop }

// traceTab is the trippy/mtr-style hop table: traceroute plus a continuous ping
// of every hop, refreshing loss and RTT stats live.
type traceTab struct {
	sty   styles
	input textinput.Model
	w, h  int
	ch    chan tea.Msg

	running bool
	host    string
	cancel  context.CancelFunc
	hops    []trace.Hop
	err     error
}

func newTraceTab() tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "8.8.8.8 или ya.ru"
	ti.CharLimit = 253
	ti.Prompt = "Цель: "
	ti.Focus()
	return &traceTab{sty: s, input: ti}
}

func (t *traceTab) Title() string { return "Трейс" }
func (t *traceTab) Init() tea.Cmd { return textinput.Blink }

func (t *traceTab) ShortHelp() []string {
	return []string{"[Enter] старт/стоп", "живые потери и RTT по хопам"}
}

func (t *traceTab) Capturing() bool  { return t.input.Focused() }
func (t *traceTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *traceTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	t.host = host
	t.running = true
	t.hops = nil
	t.err = nil
	t.input.Blur()

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 16)
	t.ch = ch
	go func() {
		err := trace.Trace(ctx, trace.Options{Host: host, MaxHops: 30}, func(hops []trace.Hop) {
			select {
			case ch <- traceHopsMsg{hops}:
			case <-ctx.Done():
			}
		})
		ch <- engineDoneMsg{err}
	}()
	return listen(ch)
}

func (t *traceTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
	t.input.Focus()
}

func (t *traceTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if t.running {
				t.stop()
				return t, nil
			}
			return t, t.start()
		}

	case traceHopsMsg:
		if t.ch == nil {
			return t, nil
		}
		t.hops = msg.hops
		return t, listen(t.ch)

	case engineDoneMsg:
		t.running = false
		if msg.err != nil {
			t.err = msg.err
		}
		t.input.Focus()
		return t, nil
	}

	if !t.running {
		var cmd tea.Cmd
		t.input, cmd = t.input.Update(msg)
		return t, cmd
	}
	return t, nil
}

func (t *traceTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.err != nil:
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
	case t.running || len(t.hops) > 0:
		state := t.sty.good.Render("● трассировка")
		if !t.running {
			state = t.sty.muted.Render("■ стоп")
		}
		fmt.Fprintf(&b, "%s  до %s\n\n", state, t.sty.accent.Render(t.host))
		b.WriteString(t.table())
	default:
		b.WriteString(t.sty.muted.Render("Трассировка пути до цели + непрерывный пинг каждого узла:\nпотери и задержка по хопам обновляются вживую (без прав администратора)."))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Трассировка + пинг", t.w, t.h, b.String()))
}

func (t *traceTab) table() string {
	nameW := t.w - 46
	if nameW < 14 {
		nameW = 14
	}
	var b strings.Builder
	header := fmt.Sprintf("%-3s %-*s %6s %7s %7s %7s", "#", nameW, "Хост", "Потери", "Посл", "Сред", "Худш")
	b.WriteString(t.sty.muted.Render(header))
	b.WriteString("\n")

	for _, h := range t.hops {
		name := hopName(h)
		name = padRight(trunc(name, nameW), nameW)

		if h.Recv == 0 {
			fmt.Fprintf(&b, "%-3d %s %s %7s %7s %7s\n",
				h.TTL, t.sty.muted.Render(name),
				t.sty.bad.Render(fmt.Sprintf("%5.0f%%", h.LossPct)), "-", "-", "-")
			continue
		}
		lossStyle := t.sty.good
		if h.LossPct > 0 {
			lossStyle = t.sty.warn
		}
		fmt.Fprintf(&b, "%-3d %s %s %7.1f %7.1f %7.1f\n",
			h.TTL, t.sty.big.Render(name),
			lossStyle.Render(fmt.Sprintf("%5.0f%%", h.LossPct)),
			h.LastMs, h.AvgMs, h.WorstMs)
	}
	return b.String()
}

func hopName(h trace.Hop) string {
	if h.Host == "" {
		return "* (нет ответа)"
	}
	if h.Name != "" {
		return h.Name + " (" + h.Host + ")"
	}
	return h.Host
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
