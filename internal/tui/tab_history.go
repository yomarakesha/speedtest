package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"speedtest/internal/history"

	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// historyLoadedMsg carries the records read from disk.
type historyLoadedMsg struct {
	recs []history.Record
	err  error
}

// historyExportedMsg reports the outcome of an export action.
type historyExportedMsg struct {
	path string
	err  error
}

// histReserveV is the vertical space above the table (trend graph + headers).
const histReserveV = 11

// historyTab shows a download-speed trend sparkline and a scrollable table of
// past runs, and can export the log to CSV/JSON.
type historyTab struct {
	sty    styles
	w, h   int
	recs   []history.Record
	tbl    table.Model
	err    error
	status string
}

func newHistoryTab() tab {
	return &historyTab{sty: newStyles(), tbl: newTable(historyColumns(80), 8)}
}

func (t *historyTab) Title() string { return "История" }
func (t *historyTab) Busy() bool    { return false }

func (t *historyTab) Init() tea.Cmd {
	return func() tea.Msg {
		recs, err := history.Load()
		return historyLoadedMsg{recs, err}
	}
}

func (t *historyTab) ShortHelp() []string {
	return []string{"[↑/↓] прокрутка", "[r] обновить", "[c] экспорт CSV", "[j] экспорт JSON"}
}

func (t *historyTab) Capturing() bool { return false }

func (t *historyTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(historyColumns(w))
	t.tbl.SetHeight(max(h-histReserveV, 3))
}

// historyColumns sizes columns to width: time/kind fixed, details take the rest.
func historyColumns(w int) []table.Column {
	const timeW, kindW = 12, 9
	detailW := max(w-timeW-kindW-8, 24)
	return []table.Column{
		{Title: "Время", Width: timeW},
		{Title: "Тип", Width: kindW},
		{Title: "Результат", Width: detailW},
	}
}

func (t *historyTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			return t, t.Init()
		case "c":
			return t, t.export("csv")
		case "j":
			return t, t.export("json")
		}
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd

	case historyLoadedMsg:
		t.recs, t.err = msg.recs, msg.err
		t.refreshRows()
		return t, nil

	case historyExportedMsg:
		if msg.err != nil {
			t.status = "Ошибка экспорта: " + msg.err.Error()
		} else {
			t.status = "Экспортировано: " + msg.path
		}
		return t, nil
	}
	return t, nil
}

// refreshRows rebuilds the table rows newest-first from the loaded records.
func (t *historyTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.recs))
	for i := len(t.recs) - 1; i >= 0; i-- {
		r := t.recs[i]
		rows = append(rows, table.Row{
			r.Time.Format("01-02 15:04"),
			string(r.Kind),
			histDetail(r),
		})
	}
	t.tbl.SetRows(rows)
}

// export writes the current records to a timestamped file next to history.jsonl.
func (t *historyTab) export(format string) tea.Cmd {
	recs := t.recs
	return func() tea.Msg {
		base, err := history.Path()
		if err != nil {
			return historyExportedMsg{err: err}
		}
		dir := base[:strings.LastIndexAny(base, "/\\")+1]
		name := fmt.Sprintf("%sexport-%s.%s", dir, time.Now().Format("20060102-150405"), format)
		f, err := os.Create(name)
		if err != nil {
			return historyExportedMsg{err: err}
		}
		defer f.Close()
		if format == "csv" {
			err = history.ExportCSV(f, recs)
		} else {
			err = history.ExportJSON(f, recs)
		}
		return historyExportedMsg{path: name, err: err}
	}
}

func (t *historyTab) View() string {
	var b strings.Builder
	switch {
	case t.err != nil:
		b.WriteString(t.sty.bad.Render("Ошибка чтения истории: " + t.err.Error()))
	case len(t.recs) == 0:
		b.WriteString(t.sty.muted.Render("История пуста. Запустите любой замер — он сохранится автоматически."))
	default:
		b.WriteString(t.trend())
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "%s\n", t.sty.muted.Render(fmt.Sprintf("Всего записей: %d", len(t.recs))))
		b.WriteString(t.tbl.View())
	}
	if t.status != "" {
		b.WriteString("\n\n")
		b.WriteString(t.sty.good.Render(t.status))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("История запусков и тренды", t.w, t.h, b.String()))
}

// trend renders a sparkline of download speed across internet/lan/httpdl runs.
func (t *historyTab) trend() string {
	var vals []float64
	var peak float64
	for _, r := range t.recs {
		if r.DownloadMbps > 0 {
			vals = append(vals, r.DownloadMbps)
			peak = max(peak, r.DownloadMbps)
		}
	}
	if len(vals) == 0 {
		return t.sty.muted.Render("Нет данных о скорости загрузки для графика.")
	}
	cw := max(t.w-6, 10)
	sl := sparkline.New(cw, 4, sparkline.WithMaxValue(peak*1.1), sparkline.WithStyle(t.sty.good))
	// Show only the most recent cw samples so the graph fits.
	if len(vals) > cw {
		vals = vals[len(vals)-cw:]
	}
	for _, v := range vals {
		sl.Push(v)
	}
	sl.Draw()
	head := t.sty.big.Render("Тренд загрузки") + t.sty.muted.Render(fmt.Sprintf("   пик %s", fmtMbps(peak)))
	return head + "\n" + sl.View()
}

// histDetail is the one-line result summary for a record's table row.
func histDetail(r history.Record) string {
	switch r.Kind {
	case history.KindInternet, history.KindLAN:
		return fmt.Sprintf("%s  ↓ %s  ↑ %s  пинг %.0f мс", trunc(r.Target, 16),
			fmtMbps(r.DownloadMbps), fmtMbps(r.UploadMbps), r.PingMs)
	case history.KindHTTPDL:
		return fmt.Sprintf("%s  ↓ %s", trunc(r.Target, 28), fmtMbps(r.DownloadMbps))
	case history.KindPing:
		return fmt.Sprintf("%s  %.1f мс  потери %.0f%%", trunc(r.Target, 20), r.PingMs, r.LossPct)
	case history.KindTrace:
		return fmt.Sprintf("%s  потери %.0f%%", trunc(r.Target, 20), r.LossPct)
	}
	return r.Target
}
