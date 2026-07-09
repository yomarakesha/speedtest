package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"speedtest/internal/portscan"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type discPhaseMsg struct {
	phase       portscan.DiscoverPhase
	done, total int
}
type discHostMsg struct{ h portscan.HostResult }
type discDoneMsg struct{ err error }

// discoverTab sweeps the local subnet: liveness pass, then a port scan of each
// live host, with results filling a table as they land.
type discoverTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg

	running bool
	done    bool
	phase   portscan.DiscoverPhase
	pdone   int
	ptotal  int
	hosts   []portscan.HostResult
	err     error
}

func newDiscoverTab() tab { return &discoverTab{sty: newStyles()} }

func (t *discoverTab) Title() string { return "Обзор" }
func (t *discoverTab) Init() tea.Cmd { return nil }

func (t *discoverTab) ShortHelp() []string {
	return []string{"[Enter] обзор локальной сети", "[r] повторить"}
}

func (t *discoverTab) Capturing() bool  { return false }
func (t *discoverTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *discoverTab) start() tea.Cmd {
	t.running, t.done = true, false
	t.phase, t.pdone, t.ptotal = portscan.PhaseLiveness, 0, 0
	t.hosts, t.err = nil, nil

	ch := make(chan tea.Msg, 256)
	t.ch = ch
	go func() {
		_, err := portscan.DiscoverLive(context.Background(),
			portscan.DiscoverOptions{Timeout: 500 * time.Millisecond, Workers: 500},
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
		case "r":
			if t.done {
				return t, t.start()
			}
		}

	case discPhaseMsg:
		t.phase, t.pdone, t.ptotal = msg.phase, msg.done, msg.total
		return t, listen(t.ch)

	case discHostMsg:
		t.hosts = append(t.hosts, msg.h)
		sort.Slice(t.hosts, func(i, j int) bool { return ipLess(t.hosts[i].IP, t.hosts[j].IP) })
		return t, listen(t.ch)

	case discDoneMsg:
		t.running, t.done = false, true
		t.err = msg.err
		return t, nil
	}
	return t, nil
}

func (t *discoverTab) View() string {
	var b strings.Builder
	switch {
	case t.running:
		label := "Поиск живых хостов"
		if t.phase == portscan.PhaseScan {
			label = "Скан портов найденных хостов"
		}
		bw := t.w - 30
		if bw < 10 {
			bw = 10
		}
		frac := 0.0
		if t.ptotal > 0 {
			frac = float64(t.pdone) / float64(t.ptotal)
		}
		fmt.Fprintf(&b, "%s %s  %s %d/%d\n\n",
			t.sty.accent.Render("●"), label,
			bar(frac, bw, t.sty.accent, t.sty.muted), t.pdone, t.ptotal)
		b.WriteString(t.table())
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			fmt.Fprintf(&b, "%s\n\n", t.sty.big.Render(fmt.Sprintf("Найдено устройств: %d", len(t.hosts))))
			b.WriteString(t.table())
		}
	default:
		b.WriteString(t.sty.muted.Render("Обзор всей локальной подсети: живые устройства, их открытые порты,\nMAC-адреса и производители. Нажмите Enter."))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Обзор сети", t.w, t.h, b.String()))
}

func (t *discoverTab) table() string {
	if len(t.hosts) == 0 {
		return t.sty.muted.Render("Пока пусто...")
	}
	var b strings.Builder
	header := fmt.Sprintf("%-16s %-22s %-18s %s", "IP", "Имя", "Производитель", "Порты")
	b.WriteString(t.sty.muted.Render(header))
	b.WriteString("\n")
	for _, h := range t.hosts {
		name := trunc(h.Hostname, 22)
		vendor := trunc(h.Vendor, 18)
		ports := portsSummary(h.Open)
		fmt.Fprintf(&b, "%-16s %-22s %-18s %s\n",
			t.sty.accent.Render(fmt.Sprintf("%-16s", h.IP)),
			name, vendor, t.sty.good.Render(ports))
	}
	return b.String()
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
	for i := 0; i < 4; i++ {
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
