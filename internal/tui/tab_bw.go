package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"speedtest/internal/bwmon"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type bwRateMsg struct{ rates []bwmon.NICRate }

// bwChartH is the fixed height reserved for the aggregate throughput graphs.
const bwChartH = 7

// bwTab shows this machine's live per-interface throughput: aggregate
// download/upload sparklines plus a table of active interfaces.
type bwTab struct {
	sty    styles
	w, h   int
	ch     chan tea.Msg
	cancel context.CancelFunc
	m      meter
	tbl    table.Model

	running bool
	rates   []bwmon.NICRate
}

func newBWTab() tab {
	return &bwTab{sty: newStyles(), m: newMeter(newStyles(), true), tbl: newTable(bwColumns(80), 8)}
}

func (t *bwTab) Title() string { return "Трафик" }
func (t *bwTab) Init() tea.Cmd { return nil }
func (t *bwTab) Busy() bool    { return t.running }

func (t *bwTab) ShortHelp() []string {
	if t.running {
		return []string{"[Enter] стоп", "[↑/↓] прокрутка"}
	}
	return []string{"[Enter] старт мониторинга", "[↑/↓] прокрутка"}
}

func (t *bwTab) Capturing() bool { return false }

func (t *bwTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.m.setSize(w, bwChartH, 2)
	t.tbl.SetColumns(bwColumns(w))
	t.tbl.SetHeight(max(h-bwChartH-5, 3))
}

func bwColumns(w int) []table.Column {
	const rxW, txW, curW = 12, 12, 12
	nameW := max(w-rxW-txW-curW-10, 12)
	return []table.Column{
		{Title: "Интерфейс", Width: nameW},
		{Title: "Приём", Width: rxW},
		{Title: "Передача", Width: txW},
		{Title: "Всего", Width: curW},
	}
}

func (t *bwTab) start() tea.Cmd {
	t.running = true
	t.m.reset()
	t.rates = nil
	t.tbl.SetRows(nil)

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 8)
	t.ch = ch
	go func() {
		_ = bwmon.Monitor(ctx, time.Second, func(r []bwmon.NICRate) {
			ch <- bwRateMsg{r}
		})
	}()
	return tea.Batch(listen(ch), t.m.spin.Tick)
}

func (t *bwTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
}

func (t *bwTab) Update(msg tea.Msg) (tab, tea.Cmd) {
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

	case bwRateMsg:
		if !t.running {
			return t, nil
		}
		rx, tx := bwmon.Totals(msg.rates)
		t.m.pushDown(rx)
		t.m.pushUp(tx)
		t.rates = msg.rates
		t.refreshRows()
		return t, listen(t.ch)

	case spinner.TickMsg:
		if !t.running {
			return t, nil
		}
		return t, t.m.tick(msg)
	}
	return t, nil
}

func (t *bwTab) refreshRows() {
	active := make([]bwmon.NICRate, 0, len(t.rates))
	for _, r := range t.rates {
		if r.RxMbps >= 0.01 || r.TxMbps >= 0.01 {
			active = append(active, r)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].RxMbps+active[i].TxMbps > active[j].RxMbps+active[j].TxMbps
	})
	rows := make([]table.Row, 0, len(active))
	for _, r := range active {
		rows = append(rows, table.Row{
			trunc(r.Name, 28),
			fmt.Sprintf("%.2f Мбит/с", r.RxMbps),
			fmt.Sprintf("%.2f Мбит/с", r.TxMbps),
			fmt.Sprintf("%.2f Мбит/с", r.RxMbps+r.TxMbps),
		})
	}
	t.tbl.SetRows(rows)
}

func (t *bwTab) View() string {
	var b strings.Builder
	if !t.running && len(t.rates) == 0 {
		b.WriteString(t.sty.muted.Render(
			"Живой трафик интерфейсов ЭТОЙ машины (приём/передача).\n" +
				"Показывает только собственный трафик хоста. Нажмите Enter."))
		return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
			t.sty.frame("Трафик", t.w, t.h, b.String()))
	}

	rx, tx := bwmon.Totals(t.rates)
	status := t.sty.muted.Render("остановлено")
	if t.running {
		status = t.sty.accent.Render(t.m.spin.View() + " идёт замер")
	}
	fmt.Fprintf(&b, "%s   всего ↓ %s  ↑ %s\n\n",
		status, t.sty.good.Render(fmtMbps(rx)), t.sty.accent.Render(fmtMbps(tx)))
	b.WriteString(t.m.charts("Приём ↓", "Передача ↑"))
	b.WriteString("\n\n")
	b.WriteString(t.tbl.View())

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Трафик", t.w, t.h, b.String()))
}
