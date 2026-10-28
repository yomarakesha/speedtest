package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/history"
	st "speedtest/internal/speedtest"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// inetProgressMsg carries one live Progress update from the engine.
type inetProgressMsg struct{ p st.Progress }

// inetResultMsg carries the final measurement.
type inetResultMsg struct {
	res st.Result
	err error
}

// internetTab is the live internet speed dashboard: ping, then live
// download/upload graphs + gauges with instantaneous and final numbers.
type internetTab struct {
	sty   styles
	m     meter
	w, h  int
	ch    chan tea.Msg
	state inetState

	phase  st.Phase
	pingMs float64
	res    st.Result
	err    error
}

type inetState int

const (
	inetIdle inetState = iota
	inetRunning
	inetDone
)

// inetReserveV is the vertical space above the graphs (spinner + summary rows).
const inetReserveV = 9

func newInternetTab() tab {
	s := newStyles()
	return &internetTab{sty: s, m: newMeter(s, true)}
}

func (t *internetTab) Title() string { return "Интернет" }
func (t *internetTab) Init() tea.Cmd { return nil }
func (t *internetTab) Busy() bool    { return t.state == inetRunning }

func (t *internetTab) ShortHelp() []string {
	return []string{"[Enter] запустить замер", "[r] повторить"}
}

func (t *internetTab) Capturing() bool { return false }

func (t *internetTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.m.setSize(w, h, inetReserveV)
}

// start kicks off the measurement goroutine.
func (t *internetTab) start() tea.Cmd {
	t.m.reset()
	t.state = inetRunning
	t.phase = st.PhasePing
	t.pingMs = 0
	t.res, t.err = st.Result{}, nil

	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := st.Run(context.Background(), st.Options{}, func(p st.Progress) {
			ch2 <- inetProgressMsg{p}
		})
		ch2 <- inetResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.m.spin.Tick)
}

func (t *internetTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if t.state != inetRunning {
				return t, t.start()
			}
		case "r":
			if t.state == inetDone {
				return t, t.start()
			}
		}

	case spinner.TickMsg:
		if t.state == inetRunning {
			return t, t.m.tick(msg)
		}
		return t, nil

	case inetProgressMsg:
		p := msg.p
		t.phase = p.Phase
		switch p.Phase {
		case st.PhasePing:
			t.pingMs = p.PingMs
		case st.PhaseDownload:
			t.m.pushDown(p.Mbps)
		case st.PhaseUpload:
			t.m.pushUp(p.Mbps)
		}
		return t, listen(t.ch)

	case inetResultMsg:
		t.state = inetDone
		t.res, t.err = msg.res, msg.err
		t.phase = st.PhaseDone
		if t.err == nil {
			_ = history.Append(history.Record{
				Kind:         history.KindInternet,
				DownloadMbps: t.res.DownloadMbps,
				UploadMbps:   t.res.UploadMbps,
				PingMs:       t.res.PingMs,
			})
		}
		return t, nil
	}
	return t, nil
}

func (t *internetTab) View() string {
	var b strings.Builder
	switch t.state {
	case inetIdle:
		b.WriteString(t.sty.muted.Render("Замер скорости через Yandex (пинг, загрузка, отдача)."))
		b.WriteString("\n\n")
		b.WriteString("Нажмите ")
		b.WriteString(t.sty.key.Render("Enter"))
		b.WriteString(" для запуска.")

	case inetRunning:
		b.WriteString(t.m.spin.View())
		b.WriteString(" ")
		b.WriteString(t.phaseLabel())
		b.WriteString("\n\n")
		b.WriteString(t.m.charts("↓ загрузка", "↑ отдача"))

	case inetDone:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
			b.WriteString("\n\n")
			b.WriteString(t.sty.muted.Render("Enter — повторить."))
		} else {
			b.WriteString(t.summary())
			b.WriteString("\n\n")
			b.WriteString(t.m.charts("↓ загрузка", "↑ отдача"))
		}
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Скорость интернета", t.w, t.h, b.String()))
}

func (t *internetTab) phaseLabel() string {
	switch t.phase {
	case st.PhasePing:
		return "Пинг до сервера..."
	case st.PhaseDownload:
		return fmt.Sprintf("Загрузка: %s   пинг %.0f мс",
			t.sty.big.Render(fmtMbps(t.m.curDn)), t.pingMs)
	case st.PhaseUpload:
		return fmt.Sprintf("Отдача: %s   %s",
			t.sty.big.Render(fmtMbps(t.m.curUp)), t.m.peakDnStr())
	}
	return "Завершение..."
}

func (t *internetTab) summary() string {
	return fmt.Sprintf("Пинг %s   ↓ Загрузка %s   ↑ Отдача %s",
		t.sty.big.Render(fmt.Sprintf("%.0f мс", t.res.PingMs)),
		t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
		t.sty.accent.Render(fmtMbps(t.res.UploadMbps)))
}
