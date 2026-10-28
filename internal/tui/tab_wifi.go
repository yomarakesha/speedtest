package tui

import (
	"fmt"
	"strings"

	"speedtest/internal/wifi"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type wifiResultMsg struct {
	link wifi.Link
	aps  []wifi.AP
	err  error
}

// wifiReserveV is the vertical space above the AP table (link panel + advice).
const wifiReserveV = 9

// wifiTab surveys the wireless environment: current association plus a table of
// nearby access points and simple 2.4 GHz channel advice.
type wifiTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg
	tbl  table.Model

	running bool
	done    bool
	link    wifi.Link
	aps     []wifi.AP
	advice  string
	err     error
}

func newWiFiTab() tab {
	return &wifiTab{sty: newStyles(), tbl: newTable(wifiColumns(80), 8)}
}

func (t *wifiTab) Title() string { return "Wi-Fi" }
func (t *wifiTab) Init() tea.Cmd { return nil }
func (t *wifiTab) Busy() bool    { return t.running }

func (t *wifiTab) ShortHelp() []string {
	return []string{"[Enter] сканировать эфир", "[↑/↓] прокрутка", "[r] повторить"}
}

func (t *wifiTab) Capturing() bool { return false }

func (t *wifiTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(wifiColumns(w))
	t.tbl.SetHeight(max(h-wifiReserveV, 3))
}

func wifiColumns(w int) []table.Column {
	const sigW, chW, bandW, secW = 8, 6, 10, 8
	nameW := max(w-sigW-chW-bandW-secW-19-8, 12)
	return []table.Column{
		{Title: "SSID", Width: nameW},
		{Title: "Сигнал", Width: sigW},
		{Title: "Канал", Width: chW},
		{Title: "Диапазон", Width: bandW},
		{Title: "Защита", Width: secW},
		{Title: "BSSID", Width: 19},
	}
}

func (t *wifiTab) start() tea.Cmd {
	t.running, t.done = true, false
	t.link, t.aps, t.advice, t.err = wifi.Link{}, nil, "", nil
	t.tbl.SetRows(nil)

	ch := make(chan tea.Msg, 4)
	t.ch = ch
	go func() {
		link, aps, err := wifi.Survey()
		ch <- wifiResultMsg{link: link, aps: aps, err: err}
	}()
	return listen(ch)
}

func (t *wifiTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if !t.running {
				return t, t.start()
			}
			return t, nil
		case "r":
			if t.done {
				return t, t.start()
			}
			return t, nil
		}
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd

	case wifiResultMsg:
		t.running, t.done = false, true
		t.link, t.aps, t.err = msg.link, msg.aps, msg.err
		t.advice = wifi.ChannelAdvice(msg.aps)
		t.refreshRows()
		return t, nil
	}
	return t, nil
}

func (t *wifiTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.aps))
	for _, ap := range t.aps {
		ssid := ap.SSID
		if ssid == "" {
			ssid = "(скрытая)"
		}
		rows = append(rows, table.Row{
			trunc(ssid, 28),
			fmt.Sprintf("%d%%", ap.SignalPct),
			fmt.Sprint(ap.Channel),
			ap.Band,
			ap.Security,
			ap.BSSID,
		})
	}
	t.tbl.SetRows(rows)
}

func (t *wifiTab) View() string {
	var b strings.Builder
	switch {
	case t.running:
		fmt.Fprintf(&b, "%s Сканирую эфир...\n", t.sty.accent.Render("●"))
	case t.done && t.err != nil:
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
	case t.done:
		t.writeLink(&b)
		if len(t.aps) > 0 {
			fmt.Fprintf(&b, "%s\n\n", t.sty.big.Render(fmt.Sprintf("Сетей поблизости: %d", len(t.aps))))
			b.WriteString(t.tbl.View())
			if t.advice != "" {
				fmt.Fprintf(&b, "\n%s", t.sty.good.Render(t.advice))
			}
			fmt.Fprintf(&b, "\n%s", t.sty.muted.Render("(трафик клиентов Wi-Fi требует режима монитора — не показывается)"))
		}
	default:
		b.WriteString(t.sty.muted.Render("Обзор Wi-Fi: текущее подключение, сети поблизости, загрузка каналов.\nНажмите Enter."))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Wi-Fi", t.w, t.h, b.String()))
}

func (t *wifiTab) writeLink(b *strings.Builder) {
	if !t.link.Connected {
		fmt.Fprintf(b, "%s\n\n", t.sty.muted.Render("Активного Wi-Fi-подключения нет."))
		return
	}
	l := t.link
	ch := "—"
	if l.Channel > 0 {
		ch = fmt.Sprintf("%d (%s)", l.Channel, l.Band)
	}
	fmt.Fprintf(b, "%s  сигнал %s  канал %s  %s\n\n",
		t.sty.accent.Render(l.SSID),
		t.sty.good.Render(fmt.Sprintf("%d%%", l.SignalPct)),
		ch,
		t.sty.muted.Render(l.Security+" "+l.Radio))
}
