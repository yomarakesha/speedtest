package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/config"
	"speedtest/internal/history"
	"speedtest/internal/lan"

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

// lanReserveV is the vertical space above the graphs (server block + input +
// phase line). The server block is variable height, so keep a generous budget.
const lanReserveV = 12

// lanTab measures throughput to another machine running `speedtest lan server`.
type lanTab struct {
	sty   styles
	input textinput.Model
	m     meter
	w, h  int
	ch    chan tea.Msg

	running bool
	done    bool
	phase   lan.Phase
	latency float64
	res     lan.ClientResult
	err     error

	// Embedded server: lets this machine act as the LAN-test target without
	// running `lan server` in a separate terminal.
	srvOn     bool
	srvInfo   lan.ServerInfo
	srvCancel context.CancelFunc
	srvErr    error
}

func newLANTab(seed string) tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "192.168.1.42 или host:5201"
	ti.CharLimit = 253
	ti.Prompt = "Сервер: "
	ti.SetValue(seed)
	ti.Focus()
	return &lanTab{sty: s, input: ti, m: newMeter(s, true)}
}

func (t *lanTab) Title() string { return "Локалка" }
func (t *lanTab) Init() tea.Cmd { return textinput.Blink }
func (t *lanTab) Busy() bool    { return t.running }

func (t *lanTab) ShortHelp() []string {
	return []string{"[Enter] замер (клиент)", "[Ctrl+S] запустить/остановить сервер здесь"}
}

// toggleServer starts or stops the embedded LAN-test server on this machine.
func (t *lanTab) toggleServer() {
	if t.srvOn {
		if t.srvCancel != nil {
			t.srvCancel()
		}
		t.srvOn, t.srvCancel = false, nil
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	info, err := lan.Serve(ctx, "")
	if err != nil {
		cancel()
		t.srvErr = err
		return
	}
	t.srvCancel, t.srvInfo, t.srvErr, t.srvOn = cancel, info, nil, true
}

func (t *lanTab) Capturing() bool { return t.input.Focused() }

func (t *lanTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.m.setSize(w, h, lanReserveV)
}

func (t *lanTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	t.m.reset()
	t.running, t.done = true, false
	t.latency = 0
	t.res, t.err = lan.ClientResult{}, nil
	t.input.Blur()

	config.Remember("lan", host)
	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := lan.RunClient(context.Background(),
			lan.ClientOptions{Host: host, Bytes: lanPayloadBytes}, func(p lan.Progress) {
				ch2 <- lanProgressMsg{p}
			})
		ch2 <- lanResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.m.spin.Tick)
}

func (t *lanTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+s":
			t.toggleServer()
			return t, nil
		case "enter":
			if !t.running {
				return t, t.start()
			}
		}

	case spinner.TickMsg:
		if t.running {
			return t, t.m.tick(msg)
		}
		return t, nil

	case lanProgressMsg:
		p := msg.p
		t.phase = p.Phase
		switch p.Phase {
		case lan.PhaseLatency:
			t.latency = p.LatencyMs
		case lan.PhaseDownload:
			t.m.pushDown(p.Mbps)
		case lan.PhaseUpload:
			t.m.pushUp(p.Mbps)
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
	b.WriteString(t.serverBlock())
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.running:
		b.WriteString(t.m.spin.View())
		b.WriteString(" ")
		b.WriteString(t.phaseLabel())
		b.WriteString("\n")
		b.WriteString(t.m.charts("↓ приём", "↑ отдача"))
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			fmt.Fprintf(&b, "Задержка %s   ↓ %s   ↑ %s",
				t.sty.big.Render(fmt.Sprintf("%.2f мс", t.res.LatencyMs)),
				t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
				t.sty.accent.Render(fmtMbps(t.res.UploadMbps)))
			b.WriteString("\n")
			b.WriteString(t.m.charts("↓ приём", "↑ отдача"))
		}
	default:
		if hint := hostHint(t.sty, t.input.Value()); hint != "" {
			b.WriteString(hint)
			b.WriteString("\n")
		}
		b.WriteString(t.sty.muted.Render("Пропускная способность до другой машины в сети.\nНа второй машине запустите: speedtest lan server"))
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
			t.sty.big.Render(fmtMbps(t.m.curDn)), t.latency)
	case lan.PhaseUpload:
		return fmt.Sprintf("Отдача: %s   пик приёма %s",
			t.sty.big.Render(fmtMbps(t.m.curUp)), fmtMbps(t.m.peakDn))
	}
	return "Завершение..."
}

// serverBlock renders the embedded-server status line(s), or a hint on how to
// turn it on. Shown above the client controls.
func (t *lanTab) serverBlock() string {
	if t.srvErr != nil {
		return t.sty.bad.Render("Сервер не запущен: "+t.srvErr.Error()) + "\n\n"
	}
	if !t.srvOn {
		return t.sty.muted.Render("[Ctrl+S] — запустить сервер на этой машине (чтобы мерить с другой)") + "\n\n"
	}
	var b strings.Builder
	b.WriteString(t.sty.good.Render("● Сервер запущен, порт " + t.srvInfo.Port))
	b.WriteString("  ")
	b.WriteString(t.sty.muted.Render("[Ctrl+S] остановить"))
	b.WriteString("\n")
	b.WriteString(t.sty.muted.Render("На другой машине выберите этот адрес в поле «Сервер»:"))
	b.WriteString("\n")
	for _, a := range t.srvInfo.Addrs {
		b.WriteString("  ")
		b.WriteString(t.sty.accent.Render(a))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}
