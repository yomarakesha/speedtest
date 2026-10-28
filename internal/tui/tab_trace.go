package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"speedtest/internal/config"
	"speedtest/internal/portscan"
	"speedtest/internal/trace"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// traceHopsMsg carries a fresh hop-table snapshot from the engine.
type traceHopsMsg struct{ hops []trace.Hop }

// traceScanHopMsg carries one hop's completed port scan; traceScanDoneMsg ends
// the scan phase.
type traceScanHopMsg struct {
	ttl int
	res portscan.ScanResult
}
type traceScanDoneMsg struct{}

// traceTab is the trippy/mtr-style hop table: traceroute plus a continuous ping
// of every hop, refreshing loss and RTT stats live.
type traceTab struct {
	sty   styles
	input textinput.Model
	w, h  int
	ch    chan tea.Msg

	running bool
	host    string
	cancel  context.CancelFunc
	hops    []trace.Hop
	err     error

	scanning  bool
	scanSpec  string                      // port spec being scanned ("common" / "all")
	scanDone  int                         // hops scanned so far
	scanTotal int                         // hops to scan
	scans     map[int]portscan.ScanResult // ttl -> scan result
}

func newTraceTab(seed string) tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "8.8.8.8 или ya.ru"
	ti.CharLimit = 253
	ti.Prompt = "Цель: "
	ti.SetValue(seed)
	ti.Focus()
	return &traceTab{sty: s, input: ti}
}

func (t *traceTab) Title() string { return "Трейс" }
func (t *traceTab) Init() tea.Cmd { return textinput.Blink }
func (t *traceTab) Busy() bool    { return t.running }

func (t *traceTab) ShortHelp() []string {
	return []string{"[Enter] старт/стоп", "[s] скан хопов (common)", "[a] скан хопов (все порты)"}
}

func (t *traceTab) Capturing() bool  { return t.input.Focused() }
func (t *traceTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *traceTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	config.Remember("trace", host)
	t.host = host
	t.running = true
	t.hops = nil
	t.err = nil
	t.input.Blur()

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	ch := make(chan tea.Msg, 16)
	t.ch = ch
	go func() {
		err := trace.Trace(ctx, trace.Options{Host: host, MaxHops: 30}, func(hops []trace.Hop) {
			select {
			case ch <- traceHopsMsg{hops}:
			case <-ctx.Done():
			}
		})
		ch <- engineDoneMsg{ch: ch, err: err}
	}()
	return listen(ch)
}

func (t *traceTab) stop() {
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.running = false
	t.input.Focus()
}

// startScan port-scans every responding hop in the current table concurrently
// (hops in parallel, each hop's ports in parallel via ScanHost). It stops any
// live trace first so the tab's channel carries only scan messages.
func (t *traceTab) startScan(spec string) tea.Cmd {
	ports, err := portscan.ParsePorts(spec)
	if err != nil {
		return nil
	}
	if t.running {
		t.stop()
	}

	type hopIP struct {
		ttl int
		ip  string
	}
	seen := map[string]bool{}
	var queue []hopIP
	for _, h := range t.hops {
		if h.Host == "" || seen[h.Host] {
			continue
		}
		seen[h.Host] = true
		queue = append(queue, hopIP{h.TTL, h.Host})
	}
	if len(queue) == 0 {
		return nil
	}

	t.scanning = true
	t.scanSpec = spec
	t.scanDone = 0
	t.scanTotal = len(queue)
	t.scans = map[int]portscan.ScanResult{}
	t.input.Blur()

	ch := make(chan tea.Msg, 64)
	t.ch = ch
	go func() {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8) // cap concurrent hosts
		for _, q := range queue {
			wg.Add(1)
			sem <- struct{}{}
			go func(q hopIP) {
				defer wg.Done()
				defer func() { <-sem }()
				res := portscan.ScanHost(q.ip, ports, 500*time.Millisecond, 500, true)
				ch <- traceScanHopMsg{ttl: q.ttl, res: res}
			}(q)
		}
		wg.Wait()
		ch <- traceScanDoneMsg{}
	}()
	return listen(ch)
}

func (t *traceTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if t.scanning {
				return t, nil
			}
			if t.running {
				t.stop()
				return t, nil
			}
			return t, t.start()
		case "s":
			// Only as a command key (input blurred, e.g. during a live trace),
			// never while typing a hostname that contains 's'.
			if !t.input.Focused() && !t.scanning && len(t.hops) > 0 {
				return t, t.startScan("common")
			}
		case "a":
			if !t.input.Focused() && !t.scanning && len(t.hops) > 0 {
				return t, t.startScan("all")
			}
		}

	case traceHopsMsg:
		if t.ch == nil || t.scanning {
			return t, nil
		}
		t.hops = msg.hops
		return t, listen(t.ch)

	case traceScanHopMsg:
		if !t.scanning {
			return t, nil
		}
		t.scans[msg.ttl] = msg.res
		t.scanDone++
		return t, listen(t.ch)

	case traceScanDoneMsg:
		t.scanning = false
		t.input.Focus()
		return t, nil

	case engineDoneMsg:
		if msg.ch != t.ch { // completion from another tab's engine — ignore
			return t, nil
		}
		t.running = false
		if msg.err != nil {
			t.err = msg.err
		}
		// A scan may have stopped the trace; keep focus on the scan phase.
		if !t.scanning {
			t.input.Focus()
		}
		return t, nil
	}

	if !t.running && !t.scanning {
		var cmd tea.Cmd
		t.input, cmd = t.input.Update(msg)
		return t, cmd
	}
	return t, nil
}

func (t *traceTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.err != nil:
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
	case t.running || len(t.hops) > 0:
		state := t.sty.good.Render("● трассировка")
		switch {
		case t.scanning:
			state = t.sty.good.Render(fmt.Sprintf("● скан хопов %s %d/%d", t.scanSpec, t.scanDone, t.scanTotal))
		case !t.running:
			state = t.sty.muted.Render("■ стоп")
		}
		fmt.Fprintf(&b, "%s  до %s\n\n", state, t.sty.accent.Render(t.host))
		b.WriteString(t.table())
	default:
		if hint := hostHint(t.sty, t.input.Value()); hint != "" {
			b.WriteString(hint)
			b.WriteString("\n")
		}
		b.WriteString(t.sty.muted.Render("Трассировка пути до цели + непрерывный пинг каждого узла:\nпотери и задержка по хопам обновляются вживую (без прав администратора).\n[s] скан портов каждого узла пути, [a] — все 65535."))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Трассировка + пинг", t.w, t.h, b.String()))
}

func (t *traceTab) table() string {
	nameW := max(t.w-46, 14)
	var b strings.Builder
	header := fmt.Sprintf("%-3s %-*s %6s %7s %7s %7s", "#", nameW, "Хост", "Потери", "Посл", "Сред", "Худш")
	b.WriteString(t.sty.muted.Render(header))
	b.WriteString("\n")

	for _, h := range t.hops {
		name := hopName(h)
		name = padRight(trunc(name, nameW), nameW)

		if h.Recv == 0 {
			fmt.Fprintf(&b, "%-3d %s %s %7s %7s %7s\n",
				h.TTL, t.sty.muted.Render(name),
				t.sty.bad.Render(fmt.Sprintf("%5.0f%%", h.LossPct)), "-", "-", "-")
			continue
		}
		lossStyle := t.sty.good
		if h.LossPct > 0 {
			lossStyle = t.sty.warn
		}
		fmt.Fprintf(&b, "%-3d %s %s %7.1f %7.1f %7.1f\n",
			h.TTL, t.sty.big.Render(name),
			lossStyle.Render(fmt.Sprintf("%5.0f%%", h.LossPct)),
			h.LastMs, h.AvgMs, h.WorstMs)

		if res, ok := t.scans[h.TTL]; ok {
			b.WriteString(t.hopPorts(res))
		}
	}
	return b.String()
}

// hopPorts renders one hop's open ports as an indented block under its row.
func (t *traceTab) hopPorts(res portscan.ScanResult) string {
	if len(res.Open) == 0 {
		return "    " + t.sty.muted.Render("открытых портов нет") + "\n"
	}
	var b strings.Builder
	for _, p := range res.Open {
		svc := p.Service
		if svc == "" {
			svc = "-"
		}
		line := fmt.Sprintf("%5d  %s", p.Port, svc)
		if p.Banner != "" {
			line += "  " + trunc(p.Banner, 40)
		}
		b.WriteString("    ")
		b.WriteString(t.sty.good.Render(line))
		b.WriteString("\n")
	}
	return b.String()
}

func hopName(h trace.Hop) string {
	if h.Host == "" {
		return "* (нет ответа)"
	}
	if h.Name != "" {
		return h.Name + " (" + h.Host + ")"
	}
	return h.Host
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
