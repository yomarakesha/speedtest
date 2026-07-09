package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/history"
	"speedtest/internal/lan"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// lanProgressMsg carries one live Progress update from the LAN client.
type lanProgressMsg struct{ p lan.Progress }

// lanResultMsg carries the final LAN measurement.
type lanResultMsg struct {
	res lan.ClientResult
	err error
}

// lanTab measures throughput to another machine running `speedtest lan-serve`.
type lanTab struct {
	sty   styles
	input textinput.Model
	spin  spinner.Model
	sldn  sparkline.Model
	slup  sparkline.Model
	w, h  int
	ch    chan tea.Msg

	running bool
	done    bool
	phase   lan.Phase
	latency float64
	curMbps float64
	peakDn  float64
	peakUp  float64
	res     lan.ClientResult
	err     error
}

func newLANTab() tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "192.168.1.42 или host:5201"
	ti.CharLimit = 253
	ti.Prompt = "Сервер: "
	ti.Focus()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &lanTab{
		sty: s, input: ti, spin: sp,
		sldn: sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(s.good)),
		slup: sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(s.accent)),
	}
}

func (t *lanTab) Title() string { return "Локалка" }
func (t *lanTab) Init() tea.Cmd { return textinput.Blink }

func (t *lanTab) ShortHelp() []string {
	return []string{"[Enter] замер", "на второй машине: speedtest lan-serve"}
}

func (t *lanTab) Capturing() bool { return t.input.Focused() }

func (t *lanTab) SetSize(w, h int) {
	t.w, t.h = w, h
	cw, ch := t.chartSize()
	t.sldn.Resize(cw, ch)
	t.slup.Resize(cw, ch)
}

func (t *lanTab) chartSize() (int, int) {
	cw := (t.w - 10) / 2
	if cw < 10 {
		cw = 10
	}
	ch := t.h - 10
	if ch < 3 {
		ch = 3
	}
	return cw, ch
}

func (t *lanTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	cw, ch := t.chartSize()
	t.sldn = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(t.sty.good))
	t.slup = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(t.sty.accent))
	t.running, t.done = true, false
	t.latency, t.curMbps, t.peakDn, t.peakUp = 0, 0, 0, 0
	t.res, t.err = lan.ClientResult{}, nil
	t.input.Blur()

	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := lan.RunClient(context.Background(),
			lan.ClientOptions{Host: host, Bytes: 100 << 20}, func(p lan.Progress) {
				ch2 <- lanProgressMsg{p}
			})
		ch2 <- lanResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.spin.Tick)
}

func (t *lanTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" && !t.running {
			return t, t.start()
		}

	case spinner.TickMsg:
		if t.running {
			var cmd tea.Cmd
			t.spin, cmd = t.spin.Update(msg)
			return t, cmd
		}
		return t, nil

	case lanProgressMsg:
		p := msg.p
		t.phase = p.Phase
		switch p.Phase {
		case lan.PhaseLatency:
			t.latency = p.LatencyMs
		case lan.PhaseDownload:
			t.curMbps = p.Mbps
			if p.Mbps > t.peakDn {
				t.peakDn = p.Mbps
			}
			pushScaledSpark(&t.sldn, p.Mbps, t.peakDn)
		case lan.PhaseUpload:
			t.curMbps = p.Mbps
			if p.Mbps > t.peakUp {
				t.peakUp = p.Mbps
			}
			pushScaledSpark(&t.slup, p.Mbps, t.peakUp)
		}
		return t, listen(t.ch)

	case lanResultMsg:
		t.running, t.done = false, true
		t.res, t.err = msg.res, msg.err
		if t.err == nil {
			_ = history.Append(history.Record{
				Kind:         history.KindLAN,
				Target:       t.res.Target,
				DownloadMbps: t.res.DownloadMbps,
				UploadMbps:   t.res.UploadMbps,
				PingMs:       t.res.LatencyMs,
			})
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

func (t *lanTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.running:
		b.WriteString(t.spin.View() + " " + t.phaseLabel())
		b.WriteString("\n")
		b.WriteString(t.charts())
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			b.WriteString(fmt.Sprintf("Задержка %s   ↓ %s   ↑ %s",
				t.sty.big.Render(fmt.Sprintf("%.2f мс", t.res.LatencyMs)),
				t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
				t.sty.accent.Render(fmtMbps(t.res.UploadMbps))))
			b.WriteString("\n")
			b.WriteString(t.charts())
		}
	default:
		b.WriteString(t.sty.muted.Render("Пропускная способность до другой машины в сети.\nНа второй машине запустите: speedtest lan-serve"))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Скорость по локальной сети", t.w, t.h, b.String()))
}

func (t *lanTab) phaseLabel() string {
	switch t.phase {
	case lan.PhaseLatency:
		return "Подключение и замер задержки..."
	case lan.PhaseDownload:
		return fmt.Sprintf("Приём: %s   задержка %.2f мс",
			t.sty.big.Render(fmtMbps(t.curMbps)), t.latency)
	case lan.PhaseUpload:
		return fmt.Sprintf("Отдача: %s   пик приёма %s",
			t.sty.big.Render(fmtMbps(t.curMbps)), fmtMbps(t.peakDn))
	}
	return "Завершение..."
}

func (t *lanTab) charts() string {
	dn := t.sty.good.Render("↓ приём") + "\n" + t.sldn.View()
	up := t.sty.accent.Render("↑ отдача") + "\n" + t.slup.View()
	return lipgloss.JoinHorizontal(lipgloss.Top, dn, "    ", up)
}
