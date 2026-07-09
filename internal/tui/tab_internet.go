package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/history"
	st "speedtest/internal/speedtest"

	"github.com/NimbleMarkets/ntcharts/sparkline"
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

// internetTab is the live internet speed dashboard: ping, then animated
// download/upload sparklines with instantaneous и final numbers.
type internetTab struct {
	sty   styles
	spin  spinner.Model
	w, h  int
	sldn  sparkline.Model
	slup  sparkline.Model
	ch    chan tea.Msg
	state inetState

	phase   st.Phase
	pingMs  float64
	curMbps float64
	peakDn  float64
	peakUp  float64
	res     st.Result
	err     error
}

type inetState int

const (
	inetIdle inetState = iota
	inetRunning
	inetDone
)

func newInternetTab() tab {
	s := newStyles()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &internetTab{
		sty:  s,
		spin: sp,
		sldn: sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(s.good)),
		slup: sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(s.accent)),
	}
}

func (t *internetTab) Title() string { return "Интернет" }
func (t *internetTab) Init() tea.Cmd { return nil }

func (t *internetTab) ShortHelp() []string {
	return []string{"[Enter] запустить замер", "[r] повторить"}
}

func (t *internetTab) Capturing() bool { return false }

func (t *internetTab) SetSize(w, h int) {
	t.w, t.h = w, h
	cw, ch := t.chartSize()
	t.sldn.Resize(cw, ch)
	t.slup.Resize(cw, ch)
}

// chartSize: two sparklines side by side inside the frame; header rows eat ~7.
func (t *internetTab) chartSize() (int, int) {
	cw := (t.w - 10) / 2
	if cw < 10 {
		cw = 10
	}
	ch := t.h - 9
	if ch < 3 {
		ch = 3
	}
	return cw, ch
}

// start kicks off the measurement goroutine.
func (t *internetTab) start() tea.Cmd {
	cw, ch := t.chartSize()
	t.sldn = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(t.sty.good))
	t.slup = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(t.sty.accent))
	t.state = inetRunning
	t.phase = st.PhasePing
	t.pingMs, t.curMbps, t.peakDn, t.peakUp = 0, 0, 0, 0
	t.res, t.err = st.Result{}, nil

	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := st.Run(context.Background(), st.Options{}, func(p st.Progress) {
			ch2 <- inetProgressMsg{p}
		})
		ch2 <- inetResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.spin.Tick)
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
			var cmd tea.Cmd
			t.spin, cmd = t.spin.Update(msg)
			return t, cmd
		}
		return t, nil

	case inetProgressMsg:
		p := msg.p
		t.phase = p.Phase
		switch p.Phase {
		case st.PhasePing:
			t.pingMs = p.PingMs
		case st.PhaseDownload:
			t.curMbps = p.Mbps
			if p.Mbps > t.peakDn {
				t.peakDn = p.Mbps
			}
			pushScaledSpark(&t.sldn, p.Mbps, t.peakDn)
		case st.PhaseUpload:
			t.curMbps = p.Mbps
			if p.Mbps > t.peakUp {
				t.peakUp = p.Mbps
			}
			pushScaledSpark(&t.slup, p.Mbps, t.peakUp)
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
		b.WriteString("Нажмите " + t.sty.key.Render("Enter") + " для запуска.")

	case inetRunning:
		b.WriteString(t.spin.View() + " " + t.phaseLabel())
		b.WriteString("\n\n")
		b.WriteString(t.charts())

	case inetDone:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
			b.WriteString("\n\n" + t.sty.muted.Render("Enter — повторить."))
		} else {
			b.WriteString(t.summary())
			b.WriteString("\n\n")
			b.WriteString(t.charts())
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
			t.sty.big.Render(fmtMbps(t.curMbps)), t.pingMs)
	case st.PhaseUpload:
		return fmt.Sprintf("Отдача: %s   пик загрузки %s",
			t.sty.big.Render(fmtMbps(t.curMbps)), fmtMbps(t.peakDn))
	}
	return "Завершение..."
}

func (t *internetTab) summary() string {
	return fmt.Sprintf("Пинг %s   ↓ Загрузка %s   ↑ Отдача %s",
		t.sty.big.Render(fmt.Sprintf("%.0f мс", t.res.PingMs)),
		t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
		t.sty.accent.Render(fmtMbps(t.res.UploadMbps)))
}

func (t *internetTab) charts() string {
	dn := t.sty.good.Render("↓ загрузка") + "\n" + t.sldn.View()
	up := t.sty.accent.Render("↑ отдача") + "\n" + t.slup.View()
	return lipgloss.JoinHorizontal(lipgloss.Top, dn, "    ", up)
}
