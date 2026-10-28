package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"speedtest/internal/portscan"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// scanProgressMsg reports scan progress; scanOpenMsg reports one open port.
type scanProgressMsg struct{ done, total int }
type scanOpenMsg struct{ p portscan.PortInfo }
type scanDoneMsg struct{ res portscan.ScanResult }

// scanTab scans the TCP ports of a single host with a live progress bar and a
// growing list of open ports.
type scanTab struct {
	sty   styles
	input textinput.Model
	w, h  int
	ch    chan tea.Msg

	running bool
	done    bool
	scanned int
	total   int
	open    []portscan.PortInfo
	host    string
}

func newScanTab() tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "192.168.1.1"
	ti.CharLimit = 253
	ti.Prompt = "Хост: "
	ti.Focus()
	return &scanTab{sty: s, input: ti}
}

func (t *scanTab) Title() string { return "Скан" }
func (t *scanTab) Init() tea.Cmd { return textinput.Blink }

func (t *scanTab) ShortHelp() []string {
	return []string{"[Enter] сканировать все порты 1-65535"}
}

func (t *scanTab) Capturing() bool  { return t.input.Focused() }
func (t *scanTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *scanTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	ports, err := portscan.ParsePorts("1-65535")
	if err != nil {
		return nil
	}
	t.host = host
	t.running, t.done = true, false
	t.scanned, t.total = 0, len(ports)
	t.open = nil
	t.input.Blur()

	ch := make(chan tea.Msg, 256)
	t.ch = ch
	go func() {
		res := portscan.ScanLive(context.Background(),
			portscan.ScanOptions{Host: host, Ports: ports, Timeout: 500 * time.Millisecond, Workers: 500},
			func(done, total int) { ch <- scanProgressMsg{done, total} },
			func(p portscan.PortInfo) { ch <- scanOpenMsg{p} })
		ch <- scanDoneMsg{res}
	}()
	return listen(ch)
}

func (t *scanTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" && !t.running {
			return t, t.start()
		}

	case scanProgressMsg:
		t.scanned, t.total = msg.done, msg.total
		return t, listen(t.ch)

	case scanOpenMsg:
		t.open = append(t.open, msg.p)
		sort.Slice(t.open, func(i, j int) bool { return t.open[i].Port < t.open[j].Port })
		return t, listen(t.ch)

	case scanDoneMsg:
		t.running, t.done = false, true
		t.open = msg.res.Open
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

func (t *scanTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	if t.running || t.done {
		frac := 0.0
		if t.total > 0 {
			frac = float64(t.scanned) / float64(t.total)
		}
		bw := t.w - 30
		if bw < 10 {
			bw = 10
		}
		state := t.sty.good.Render("● скан")
		if t.done {
			state = t.sty.muted.Render("■ готово")
		}
		fmt.Fprintf(&b, "%s  %s %d/%d\n", state,
			bar(frac, bw, t.sty.accent, t.sty.muted), t.scanned, t.total)
		b.WriteString(t.openList())
	} else {
		b.WriteString(t.sty.muted.Render("Сканирование TCP-портов 1-65535 одного хоста."))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Скан портов", t.w, t.h, b.String()))
}

func (t *scanTab) openList() string {
	if len(t.open) == 0 {
		if t.done {
			return "\n" + t.sty.muted.Render("Открытых портов не найдено.")
		}
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(t.sty.big.Render(fmt.Sprintf("Открыто (%d):", len(t.open))))
	b.WriteString("\n")
	for _, p := range t.open {
		svc := p.Service
		if svc == "" {
			svc = "-"
		}
		fmt.Fprintf(&b, "  %s  %s\n",
			t.sty.good.Render(fmt.Sprintf("%5d", p.Port)),
			t.sty.muted.Render(svc))
	}
	return b.String()
}
