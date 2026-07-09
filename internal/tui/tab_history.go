package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"speedtest/internal/history"

	"github.com/NimbleMarkets/ntcharts/sparkline"
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

// historyTab shows recent runs and a download-speed trend sparkline, and can
// export the log to CSV/JSON.
type historyTab struct {
	sty    styles
	w, h   int
	recs   []history.Record
	err    error
	status string
}

func newHistoryTab() tab { return &historyTab{sty: newStyles()} }

func (t *historyTab) Title() string { return "История" }

func (t *historyTab) Init() tea.Cmd {
	return func() tea.Msg {
		recs, err := history.Load()
		return historyLoadedMsg{recs, err}
	}
}

func (t *historyTab) ShortHelp() []string {
	return []string{"[r] обновить", "[c] экспорт CSV", "[j] экспорт JSON"}
}

func (t *historyTab) Capturing() bool  { return false }
func (t *historyTab) SetSize(w, h int) { t.w, t.h = w, h }

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

	case historyLoadedMsg:
		t.recs, t.err = msg.recs, msg.err
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
		b.WriteString(t.recent())
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
			if r.DownloadMbps > peak {
				peak = r.DownloadMbps
			}
		}
	}
	if len(vals) == 0 {
		return t.sty.muted.Render("Нет данных о скорости загрузки для графика.")
	}
	cw := t.w - 6
	if cw < 10 {
		cw = 10
	}
	sl := sparkline.New(cw, 5, sparkline.WithMaxValue(peak*1.1), sparkline.WithStyle(t.sty.good))
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

// recent lists the last runs, newest first.
func (t *historyTab) recent() string {
	var b strings.Builder
	b.WriteString(t.sty.muted.Render(fmt.Sprintf("Всего записей: %d — последние:", len(t.recs))))
	b.WriteString("\n")

	max := t.h - 12
	if max < 3 {
		max = 3
	}
	start := 0
	if len(t.recs) > max {
		start = len(t.recs) - max
	}
	for i := len(t.recs) - 1; i >= start; i-- {
		r := t.recs[i]
		fmt.Fprintf(&b, "  %s  %s  %s\n",
			t.sty.muted.Render(r.Time.Format("01-02 15:04")),
			t.sty.accent.Render(fmt.Sprintf("%-8s", r.Kind)),
			histLine(t.sty, r))
	}
	return b.String()
}

func histLine(sty styles, r history.Record) string {
	switch r.Kind {
	case history.KindInternet, history.KindLAN:
		return fmt.Sprintf("%s ↓ %s ↑ %s  пинг %.0f мс", trunc(r.Target, 16),
			sty.good.Render(fmtMbps(r.DownloadMbps)),
			sty.accent.Render(fmtMbps(r.UploadMbps)), r.PingMs)
	case history.KindHTTPDL:
		return fmt.Sprintf("%s  ↓ %s", trunc(r.Target, 24), sty.good.Render(fmtMbps(r.DownloadMbps)))
	case history.KindPing:
		return fmt.Sprintf("%s  %.1f мс  потери %.0f%%", trunc(r.Target, 20), r.PingMs, r.LossPct)
	case history.KindTrace:
		return fmt.Sprintf("%s  потери %.0f%%", trunc(r.Target, 20), r.LossPct)
	}
	return r.Target
}
