package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/capture"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type appRateMsg struct {
	procs []capture.ProcTraffic
	err   error
}

// appsTab shows live per-process network throughput: which application is
// using how much bandwidth right now, plus a "Система/неизвестно" bucket for
// traffic that couldn't be matched to a process.
type appsTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg

	cancel context.CancelFunc
	spin   spinner.Model
	tbl    table.Model

	running bool
	procs   []capture.ProcTraffic
	err     error
}

func newAppsTab() tab {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sty := newStyles()
	sp.Style = sty.accent
	return &appsTab{sty: sty, spin: sp, tbl: newTable(appsColumns(80), 10)}
}

func (t *appsTab) Title() string { return "Приложения" }
func (t *appsTab) Init() tea.Cmd { return nil }
func (t *appsTab) Busy() bool    { return t.running }

func (t *appsTab) ShortHelp() []string {
	if !capture.Available() {
		return nil
	}
	if t.running {
		return []string{"[Enter] стоп", "[↑/↓] прокрутка"}
	}
	return []string{"[Enter] старт мониторинга", "[↑/↓] прокрутка"}
}

func (t *appsTab) Capturing() bool { return false }

func (t *appsTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(appsColumns(w))
	t.tbl.SetHeight(max(h-6, 3))
}

func appsColumns(w int) []table.Column {
	const pidW, rxW, txW, totW = 8, 12, 12, 12
	nameW := max(w-pidW-rxW-txW-totW-10, 12)
	return []table.Column{
		{Title: "PID", Width: pidW},
		{Title: "Процесс", Width: nameW},
		{Title: "Приём", Width: rxW},
		{Title: "Передача", Width: txW},
		{Title: "Всего", Width: totW},
	}
}

func (t *appsTab) start() tea.Cmd {
	t.running = true
	t.err = nil
	t.procs = nil
	t.tbl.SetRows(nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 8)
	t.ch = ch
	go func() {
		err := capture.TopProcesses(ctx, capture.Options{Interval: time.Second}, func(p []capture.ProcTraffic) {
			ch <- appRateMsg{procs: p}
		})
		if err != nil && ctx.Err() == nil {
			ch <- appRateMsg{err: err}
		}
	}()
	return tea.Batch(listen(ch), t.spin.Tick)
}

func (t *appsTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
}

func (t *appsTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	if !capture.Available() {
		return t, nil
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if t.running {
				t.stop()
			} else {
				return t, t.start()
			}
			return t, nil
		}
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd

	case appRateMsg:
		if !t.running {
			return t, nil
		}
		if msg.err != nil {
			t.err = msg.err
			t.stop()
			return t, nil
		}
		t.procs = msg.procs
		t.refreshRows()
		return t, listen(t.ch)

	case spinner.TickMsg:
		if !t.running {
			return t, nil
		}
		var cmd tea.Cmd
		t.spin, cmd = t.spin.Update(msg)
		return t, cmd
	}
	return t, nil
}

func (t *appsTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.procs))
	for _, p := range t.procs {
		pid := fmt.Sprintf("%d", p.PID)
		if p.PID == 0 {
			pid = "-"
		}
		rows = append(rows, table.Row{
			pid,
			trunc(p.Name, 28),
			fmt.Sprintf("%.2f Мбит/с", p.RxMbps),
			fmt.Sprintf("%.2f Мбит/с", p.TxMbps),
			fmt.Sprintf("%.2f Мбит/с", p.RxMbps+p.TxMbps),
		})
	}
	t.tbl.SetRows(rows)
}

func (t *appsTab) View() string {
	var b strings.Builder

	if !capture.Available() {
		b.WriteString(t.sty.muted.Render(
			"Трафик по приложениям требует захвата пакетов.\n" +
				"Соберите с -tags pcap (нужен Npcap на Windows) — обычной сборкой недоступно."))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	if t.err != nil {
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	if !t.running && len(t.procs) == 0 {
		b.WriteString(t.sty.muted.Render(
			"Живой трафик по процессам этой машины (кто сколько качает).\n" +
				"Неопознанный трафик попадает в «Система/неизвестно». Нажмите Enter."))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Приложения", t.w, t.h, b.String()))
	}

	status := t.sty.muted.Render("остановлено")
	if t.running {
		status = t.sty.accent.Render(t.spin.View() + " идёт замер")
	}
	fmt.Fprintf(&b, "%s\n\n", status)
	b.WriteString(t.tbl.View())

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Приложения", t.w, t.h, b.String()))
}
