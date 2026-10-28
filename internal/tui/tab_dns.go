package tui

import (
	"fmt"
	"strings"
	"time"

	"speedtest/internal/dnsbench"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// dnsResultMsg carries the finished resolver comparison.
type dnsResultMsg struct{ results []dnsbench.ServerResult }

// dnsTab compares DNS resolver response times against the built-in domain
// and server list (see internal/dnsbench).
type dnsTab struct {
	sty  styles
	spin spinner.Model
	w, h int
	ch   chan tea.Msg

	running bool
	done    bool
	results []dnsbench.ServerResult
}

func newDNSTab() tab {
	s := newStyles()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &dnsTab{sty: s, spin: sp}
}

func (t *dnsTab) Title() string { return "DNS" }
func (t *dnsTab) Init() tea.Cmd { return nil }

func (t *dnsTab) ShortHelp() []string {
	return []string{"[Enter] сравнить резолверы"}
}

func (t *dnsTab) Capturing() bool  { return false }
func (t *dnsTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *dnsTab) start() tea.Cmd {
	if t.running {
		return nil
	}
	t.running, t.done = true, false
	t.results = nil

	ch := make(chan tea.Msg, 1)
	t.ch = ch
	go func() {
		res := dnsbench.Bench(dnsbench.DefaultDomains, dnsbench.DefaultServers, 3*time.Second)
		ch <- dnsResultMsg{res}
	}()
	return tea.Batch(listen(ch), t.spin.Tick)
}

func (t *dnsTab) Update(msg tea.Msg) (tab, tea.Cmd) {
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

	case dnsResultMsg:
		t.running, t.done = false, true
		t.results = msg.results
		return t, nil
	}
	return t, nil
}

func (t *dnsTab) View() string {
	var b strings.Builder

	switch {
	case t.running:
		fmt.Fprintf(&b, "%s Опрашиваю резолверы по %d доменам...\n", t.spin.View(), len(dnsbench.DefaultDomains))
	case t.done:
		b.WriteString(t.table())
	default:
		fmt.Fprintf(&b, "Сравнение скорости ответа DNS-резолверов на %d доменах:\n%s\n\n[Enter] — запустить сравнение",
			len(dnsbench.DefaultDomains), t.sty.muted.Render(strings.Join(dnsbench.DefaultDomains, ", ")))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("DNS-резолверы", t.w, t.h, b.String()))
}

func (t *dnsTab) table() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-14s %8s %8s %8s %8s\n", "Резолвер", "сред.мс", "мин.мс", "макс.мс", "ошибки")
	for _, r := range t.results {
		fails := fmt.Sprintf("%d/%d", r.Failures, r.Total)
		if r.Failures == r.Total {
			fmt.Fprintf(&b, "%-14s %8s %8s %8s %8s\n", r.Server, "—", "—", "—", fails)
			continue
		}
		fmt.Fprintf(&b, "%-14s %8.1f %8.1f %8.1f %8s\n", r.Server, r.AvgMs, r.MinMs, r.MaxMs, fails)
	}
	return b.String()
}

func (t *dnsTab) Busy() bool { return t.running }
