package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"speedtest/internal/config"
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
	addr    string // address the name resolved to, once the scan finishes
	warning string
	failure string
	web     []portscan.WebInfo
	subs    *portscan.SubdomainResult
	portIdx int // index into scanPresets
}

// scanPresets are the port ranges the Scan tab can cycle through with [p].
// 1-1024 covers well-known services fast; the full range catches high ports
// (databases, RDP, alt-HTTP like 3306/3389/8080) at the cost of speed.
var scanPresets = []struct{ label, spec string }{
	{"1-1024 (быстро)", "1-1024"},
	{"1-65535 (все)", "1-65535"},
}

func newScanTab(seed string) tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "192.168.1.1"
	ti.CharLimit = 253
	ti.Prompt = "Хост: "
	ti.SetValue(seed)
	ti.Focus()
	return &scanTab{sty: s, input: ti}
}

func (t *scanTab) Title() string { return "Скан" }
func (t *scanTab) Init() tea.Cmd { return textinput.Blink }
func (t *scanTab) Busy() bool    { return t.running }

func (t *scanTab) ShortHelp() []string {
	return []string{"[Enter] сканировать", "[p] диапазон: " + scanPresets[t.portIdx].label}
}

func (t *scanTab) Capturing() bool  { return t.input.Focused() }
func (t *scanTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *scanTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	ports, err := portscan.ParsePorts(scanPresets[t.portIdx].spec)
	if err != nil {
		return nil
	}
	config.Remember("scan", host)
	t.host = host
	t.running, t.done = true, false
	t.scanned, t.total = 0, len(ports)
	t.open = nil
	t.addr, t.warning, t.failure, t.subs, t.web = "", "", "", nil, nil
	t.input.Blur()

	ch := make(chan tea.Msg, 256)
	t.ch = ch
	go func() {
		res := portscan.ScanLive(context.Background(),
			portscan.ScanOptions{Host: host, Ports: ports, Timeout: scanTimeout,
				Workers: scanWorkers, Subdomains: true, Fingerprint: true},
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
		if msg.String() == "p" && !t.running {
			t.portIdx = (t.portIdx + 1) % len(scanPresets)
			return t, nil
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
		t.warning, t.failure = msg.res.Warning, msg.res.Error
		t.subs = msg.res.Subdomains
		t.web = msg.res.Web
		if msg.res.Host != t.host {
			t.addr = msg.res.Host
		}
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
		bw := max(t.w-30, 10)
		state := t.sty.good.Render("● скан")
		if t.done {
			state = t.sty.muted.Render("■ готово")
		}
		fmt.Fprintf(&b, "%s  %s %d/%d\n", state,
			bar(frac, bw, t.sty.accent, t.sty.muted), t.scanned, t.total)
		if t.failure != "" {
			fmt.Fprintln(&b, t.sty.bad.Render(t.failure))
		} else {
			if t.addr != "" {
				fmt.Fprintln(&b, t.sty.muted.Render("адрес: "+t.addr))
			}
			if t.warning != "" {
				fmt.Fprintln(&b, t.sty.warn.Render(t.warning))
			}
			b.WriteString(t.openList())
			b.WriteString(t.webList())
			b.WriteString(t.subList())
		}
	} else if hint := hostHint(t.sty, t.input.Value()); hint != "" {
		b.WriteString(hint)
	} else {
		b.WriteString(t.sty.muted.Render("Сканирование TCP-портов " + scanPresets[t.portIdx].spec + " одного хоста."))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Скан портов", t.w, t.h, b.String()))
}

// webList renders the fingerprint of each open web port: status, server, and
// the technologies detected.
func (t *scanTab) webList() string {
	if len(t.web) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(t.sty.big.Render("Веб-сервисы:"))
	b.WriteString("\n")
	for _, w := range t.web {
		head := fmt.Sprintf("%d/%s  %d", w.Port, w.Scheme, w.Status)
		if w.Server != "" {
			head += "  " + w.Server
		}
		if len(w.Tech) > 0 {
			head += "  [" + strings.Join(w.Tech, ", ") + "]"
		}
		fmt.Fprintf(&b, "  %s\n", t.sty.good.Render(head))
		if w.Title != "" {
			fmt.Fprintf(&b, "    %s\n", t.sty.muted.Render(w.Title))
		}
		if w.Redirect != "" {
			fmt.Fprintf(&b, "    %s\n", t.sty.muted.Render("-> "+w.Redirect))
		}
	}
	return b.String()
}

// subList renders the subdomains found under the scanned zone. The panel is
// short, so only the first few are listed and the rest are counted.
func (t *scanTab) subList() string {
	if t.subs == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	if len(t.subs.Found) == 0 {
		return b.String() + t.sty.muted.Render("Субдоменов "+t.subs.Base+" не найдено.") + "\n"
	}
	b.WriteString(t.sty.big.Render(fmt.Sprintf("Субдомены %s (%d):", t.subs.Base, len(t.subs.Found))))
	b.WriteString("\n")
	const shown = 8
	for i, s := range t.subs.Found {
		if i == shown {
			fmt.Fprintf(&b, "  %s\n", t.sty.muted.Render(fmt.Sprintf("... ещё %d", len(t.subs.Found)-shown)))
			break
		}
		fmt.Fprintf(&b, "  %s  %s\n", t.sty.good.Render(s.Name),
			t.sty.muted.Render(strings.Join(s.Addrs, ", ")))
	}
	return b.String()
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
