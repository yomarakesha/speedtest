package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"speedtest/internal/portscan"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type discPhaseMsg struct {
	phase       portscan.DiscoverPhase
	done, total int
}
type discHostMsg struct{ h portscan.HostResult }
type discDoneMsg struct{ err error }

// discReserveV is the vertical space above the table (progress/summary + blank).
const discReserveV = 4

// discoverTab sweeps the local subnet: liveness pass, then a port scan of each
// live host, with results filling a scrollable table as they land.
type discoverTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg
	tbl  table.Model

	running    bool
	done       bool
	allSubnets bool
	phase      portscan.DiscoverPhase
	pdone   int
	ptotal  int
	hosts   []portscan.HostResult
	err     error
}

func newDiscoverTab() tab {
	return &discoverTab{sty: newStyles(), tbl: newTable(discoverColumns(80), 10)}
}

func (t *discoverTab) Title() string { return "Обзор" }
func (t *discoverTab) Init() tea.Cmd { return nil }
func (t *discoverTab) Busy() bool    { return t.running }

func (t *discoverTab) ShortHelp() []string {
	scope := "[a] все подсети: выкл"
	if t.allSubnets {
		scope = "[a] все подсети: вкл"
	}
	return []string{"[Enter] обзор локальной сети", scope, "[↑/↓] прокрутка", "[r] повторить"}
}

func (t *discoverTab) Capturing() bool { return false }

func (t *discoverTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(discoverColumns(w))
	t.tbl.SetHeight(max(h-discReserveV, 3))
}

// discoverColumns sizes the columns to the available width: IP/vendor fixed,
// name and ports share the slack.
func discoverColumns(w int) []table.Column {
	const ipW, vendorW = 15, 16
	rest := max(w-ipW-vendorW-8, 20)
	nameW := rest * 3 / 5
	portsW := rest - nameW
	return []table.Column{
		{Title: "IP", Width: ipW},
		{Title: "Имя", Width: nameW},
		{Title: "Производитель", Width: vendorW},
		{Title: "Порты", Width: portsW},
	}
}

func (t *discoverTab) start() tea.Cmd {
	t.running, t.done = true, false
	t.phase, t.pdone, t.ptotal = portscan.PhaseLiveness, 0, 0
	t.hosts, t.err = nil, nil
	t.tbl.SetRows(nil)

	ch := make(chan tea.Msg, 256)
	t.ch = ch
	go func() {
		_, err := portscan.DiscoverLive(context.Background(),
			portscan.DiscoverOptions{Timeout: discoverTimeout, Workers: discoverWorkers, AllSubnets: t.allSubnets},
			func(p portscan.DiscoverPhase, done, total int) { ch <- discPhaseMsg{p, done, total} },
			func(h portscan.HostResult) { ch <- discHostMsg{h} })
		ch <- discDoneMsg{err}
	}()
	return listen(ch)
}

func (t *discoverTab) Update(msg tea.Msg) (tab, tea.Cmd) {
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
		case "a":
			if !t.running {
				t.allSubnets = !t.allSubnets
			}
			return t, nil
		}
		// Other keys (↑/↓/pgup/pgdn/home/end) scroll the table.
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd

	case discPhaseMsg:
		t.phase, t.pdone, t.ptotal = msg.phase, msg.done, msg.total
		return t, listen(t.ch)

	case discHostMsg:
		t.hosts = append(t.hosts, msg.h)
		sort.Slice(t.hosts, func(i, j int) bool { return ipLess(t.hosts[i].IP, t.hosts[j].IP) })
		t.refreshRows()
		return t, listen(t.ch)

	case discDoneMsg:
		t.running, t.done = false, true
		t.err = msg.err
		return t, nil
	}
	return t, nil
}

func (t *discoverTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.hosts))
	for _, h := range t.hosts {
		rows = append(rows, table.Row{
			h.IP,
			trunc(h.Hostname, 28),
			trunc(h.Vendor, 16),
			portsSummary(h.Open),
		})
	}
	t.tbl.SetRows(rows)
}

func (t *discoverTab) View() string {
	var b strings.Builder
	switch {
	case t.running:
		label := "Поиск живых хостов"
		if t.phase == portscan.PhaseScan {
			label = "Скан портов найденных хостов"
		}
		bw := max(t.w-30, 10)
		frac := 0.0
		if t.ptotal > 0 {
			frac = float64(t.pdone) / float64(t.ptotal)
		}
		fmt.Fprintf(&b, "%s %s  %s %d/%d\n\n",
			t.sty.accent.Render("●"), label,
			bar(frac, bw, t.sty.accent, t.sty.muted), t.pdone, t.ptotal)
		b.WriteString(t.tbl.View())
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			fmt.Fprintf(&b, "%s\n\n", t.sty.big.Render(fmt.Sprintf("Найдено устройств: %d", len(t.hosts))))
			b.WriteString(t.tbl.View())
		}
	default:
		scope := "текущая подсеть"
		if t.allSubnets {
			scope = "ВСЕ подсети машины"
		}
		fmt.Fprintf(&b, "%s\n\n%s",
			t.sty.muted.Render("Обзор локальной сети: живые устройства, их открытые порты,\nMAC-адреса и производители. Нажмите Enter."),
			t.sty.muted.Render("Область: "+scope+"  ([a] переключить)"))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Обзор сети", t.w, t.h, b.String()))
}

func portsSummary(open []portscan.PortInfo) string {
	if len(open) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(open))
	for _, p := range open {
		parts = append(parts, fmt.Sprint(p.Port))
	}
	return strings.Join(parts, ",")
}

func trunc(s string, n int) string {
	if s == "" {
		return "-"
	}
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// ipLess compares dotted IPv4 strings numerically (best-effort; falls back to
// lexical order for anything unexpected).
func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := range 4 {
		if pa[i] != pb[i] {
			return atoiSafe(pa[i]) < atoiSafe(pb[i])
		}
	}
	return false
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
