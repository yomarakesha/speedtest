package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"speedtest/internal/portscan"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type discPhaseMsg struct {
	phase       portscan.DiscoverPhase
	done, total int
}
type discHostMsg struct{ h portscan.HostResult }
type discSubnetMsg struct{ cidr, source string }
type discDoneMsg struct{ err error }

// discReserveV is the vertical space above the results table (status line + blank).
const discReserveV = 4

// discMode is one of the four scan scopes offered by the menu.
type discMode int

const (
	modeLocal  discMode = iota // the subnet this computer is on
	modeAll                    // every subnet the computer is attached to
	modeManual                 // subnets the user types in
	modeExpand                 // auto-discover hidden subnets (traceroute + SNMP)
)

// discModes drives the on-screen menu: plain-language name + one-line help.
var discModes = []struct{ name, desc string }{
	{"Моя сеть", "сеть, к которой подключён этот компьютер"},
	{"Все мои сети", "каждая сеть этого компьютера (интерфейсы + маршруты)"},
	{"Выбрать сети вручную", "вписать адреса сетей самому"},
	{"Найти все сети", "сам обнаружит скрытые сети и просканирует (traceroute + SNMP)"},
}

// discoverTab is a menu-driven network overview. The user picks a scope from a
// plain-language list; only the fields that scope needs appear. Results fill a
// scrollable table. Modes: local subnet, all attached subnets, a hand-typed list
// of CIDRs, or an auto-discovery sweep that finds subnets the machine has no
// route for (via traceroute, and SNMP when a community is given).
type discoverTab struct {
	sty  styles
	w, h int
	ch   chan tea.Msg
	tbl  table.Model

	mode     discMode
	editing  bool // true while the user is filling in a mode's fields
	fieldIdx int  // focused field within the active mode
	noICMP   bool // liveness by TCP/ARP only, for networks that block ping

	cidrIn  textinput.Model // modeManual: subnet list
	seedIn  textinput.Model // modeExpand: optional seed subnets
	commIn  textinput.Model // modeExpand: optional SNMP community
	depthIn textinput.Model // modeExpand: recursion depth

	running bool
	done    bool
	expand  bool     // the finished/running sweep was an auto-discovery
	subnets []string // subnets discovered so far (expand mode)
	phase   portscan.DiscoverPhase
	pdone   int
	ptotal  int
	hosts   []portscan.HostResult
	err     error
}

func newDiscoverTab() tab {
	mk := func(prompt, placeholder string) textinput.Model {
		ti := textinput.New()
		ti.Prompt = prompt
		ti.Placeholder = placeholder
		ti.CharLimit = 512
		return ti
	}
	depth := mk("Глубина поиска: ", "2")
	depth.SetValue("2")
	depth.CharLimit = 2
	return &discoverTab{
		sty:     newStyles(),
		tbl:     newTable(discoverColumns(80), 10),
		cidrIn:  mk("Адреса сетей: ", "192.168.100.0/24, 10.0.0.0/24"),
		seedIn:  mk("Начать с (не обязательно): ", "192.168.100.0/24"),
		commIn:  mk("SNMP-пароль (если знаешь): ", "public"),
		depthIn: depth,
	}
}

func (t *discoverTab) Title() string { return "Скан сети" }
func (t *discoverTab) Init() tea.Cmd { return textinput.Blink }
func (t *discoverTab) Busy() bool    { return t.running }

func (t *discoverTab) ShortHelp() []string {
	switch {
	case t.running:
		return []string{"идёт обзор..."}
	case t.editing:
		return []string{"[Enter] запустить", "[↑/↓] поле", "[Esc] назад"}
	case t.done:
		return []string{"[Enter/r] повторить", "[Esc] выбрать заново", "[↑/↓] прокрутка"}
	default:
		return []string{"[↑/↓] выбрать", "[Enter] дальше", "[i] ICMP-пинг"}
	}
}

// Capturing is true only while typing into a field, so the menu's ↑/↓ and the
// results table's ↑/↓ still reach this tab (they aren't printable characters).
func (t *discoverTab) Capturing() bool { return t.editing }

func (t *discoverTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.tbl.SetColumns(discoverColumns(w))
	t.tbl.SetHeight(max(h-discReserveV, 3))
}

// discoverColumns sizes the columns to the available width: IP/MAC/vendor
// fixed, name and ports share the slack. MAC earns its place because a host can
// be found by its ARP entry alone, with no open port to show.
func discoverColumns(w int) []table.Column {
	const ipW, macW, vendorW = 15, 17, 16
	rest := max(w-ipW-macW-vendorW-10, 20)
	nameW := rest * 3 / 5
	portsW := rest - nameW
	return []table.Column{
		{Title: "IP", Width: ipW},
		{Title: "Имя", Width: nameW},
		{Title: "MAC", Width: macW},
		{Title: "Производитель", Width: vendorW},
		{Title: "Порты", Width: portsW},
	}
}

// activeFields returns the focusable inputs for the current mode, in order.
func (t *discoverTab) activeFields() []*textinput.Model {
	switch t.mode {
	case modeManual:
		return []*textinput.Model{&t.cidrIn}
	case modeExpand:
		return []*textinput.Model{&t.seedIn, &t.commIn, &t.depthIn}
	}
	return nil
}

// focusField blurs every field and focuses index i of the active mode.
func (t *discoverTab) focusField(i int) tea.Cmd {
	fields := t.activeFields()
	for _, f := range fields {
		f.Blur()
	}
	if i < 0 || i >= len(fields) {
		return nil
	}
	t.fieldIdx = i
	return fields[i].Focus()
}

// enterEditing moves from the menu into the current mode's field(s).
func (t *discoverTab) enterEditing() tea.Cmd {
	t.editing = true
	return t.focusField(0)
}

// leaveEditing returns to the menu, blurring all fields.
func (t *discoverTab) leaveEditing() {
	t.editing = false
	for _, f := range t.activeFields() {
		f.Blur()
	}
}

func (t *discoverTab) start() tea.Cmd {
	t.running, t.done = true, false
	t.phase, t.pdone, t.ptotal = portscan.PhaseLiveness, 0, 0
	t.hosts, t.subnets, t.err = nil, nil, nil
	t.expand = false
	t.tbl.SetRows(nil)
	t.leaveEditing()

	ch := make(chan tea.Msg, 256)
	t.ch = ch

	if t.mode == modeExpand {
		t.expand = true
		opt := portscan.ExpandOptions{
			Seeds:     portscan.SplitCIDRs(t.seedIn.Value()),
			Community: strings.TrimSpace(t.commIn.Value()),
			MaxDepth:  atoiSafe(strings.TrimSpace(t.depthIn.Value())),
			Timeout:   discoverTimeout,
			Workers:   discoverWorkers,
			NoICMP:    t.noICMP,
		}
		go func() {
			_, err := portscan.ExpandDiscover(context.Background(), opt,
				func(cidr, source string) { ch <- discSubnetMsg{cidr, source} },
				func(h portscan.HostResult) { ch <- discHostMsg{h} })
			ch <- discDoneMsg{err}
		}()
		return listen(ch)
	}

	opt := portscan.DiscoverOptions{Timeout: discoverTimeout, Workers: discoverWorkers, NoICMP: t.noICMP}
	switch t.mode {
	case modeAll:
		opt.AllSubnets = true
	case modeManual:
		opt.CIDRs = portscan.SplitCIDRs(t.cidrIn.Value()) // empty => local fallback below
	}
	go func() {
		_, err := portscan.DiscoverLive(context.Background(), opt,
			func(p portscan.DiscoverPhase, done, total int) { ch <- discPhaseMsg{p, done, total} },
			func(h portscan.HostResult) { ch <- discHostMsg{h} })
		ch <- discDoneMsg{err}
	}()
	return listen(ch)
}

func (t *discoverTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return t.handleKey(msg)

	case discPhaseMsg:
		t.phase, t.pdone, t.ptotal = msg.phase, msg.done, msg.total
		return t, listen(t.ch)

	case discSubnetMsg:
		t.subnets = append(t.subnets, msg.cidr)
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

// handleKey routes a keypress by the tab's current state: filling in fields,
// viewing results, a running scan, or the mode menu.
func (t *discoverTab) handleKey(msg tea.KeyMsg) (tab, tea.Cmd) {
	// Editing fields: keys type into the focused input; ↑/↓ move between fields,
	// Enter runs, Esc goes back to the menu.
	if t.editing {
		switch msg.String() {
		case "enter":
			return t, t.start()
		case "esc":
			t.leaveEditing()
			return t, nil
		case "down":
			if t.fieldIdx < len(t.activeFields())-1 {
				return t, t.focusField(t.fieldIdx + 1)
			}
			return t, nil
		case "up":
			if t.fieldIdx > 0 {
				return t, t.focusField(t.fieldIdx - 1)
			}
			t.leaveEditing() // up past the first field returns to the menu
			return t, nil
		}
		fields := t.activeFields()
		var cmd tea.Cmd
		*fields[t.fieldIdx], cmd = fields[t.fieldIdx].Update(msg)
		return t, cmd
	}

	if t.running {
		return t, nil
	}

	// Viewing results: scroll the table, repeat, or go back to the menu.
	if t.done {
		switch msg.String() {
		case "enter", "r":
			return t, t.start()
		case "esc":
			t.done = false
			return t, nil
		}
		var cmd tea.Cmd
		t.tbl, cmd = t.tbl.Update(msg)
		return t, cmd
	}

	// Menu: choose a mode, then run (local/all) or open its fields (manual/expand).
	switch msg.String() {
	case "up":
		t.mode = (t.mode - 1 + discMode(len(discModes))) % discMode(len(discModes))
		return t, nil
	case "down":
		t.mode = (t.mode + 1) % discMode(len(discModes))
		return t, nil
	case "i":
		t.noICMP = !t.noICMP
		return t, nil
	case "enter":
		if t.mode == modeManual || t.mode == modeExpand {
			return t, t.enterEditing()
		}
		return t, t.start()
	}
	return t, nil
}

func (t *discoverTab) refreshRows() {
	rows := make([]table.Row, 0, len(t.hosts))
	for _, h := range t.hosts {
		rows = append(rows, table.Row{
			h.IP,
			trunc(h.Hostname, 28),
			trunc(h.MAC, 17),
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
		t.viewRunning(&b)
	case t.done:
		t.viewResults(&b)
	default:
		t.viewMenu(&b)
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Скан сети (IP + порты)", t.w, t.h, b.String()))
}

// viewMenu renders the mode chooser plus any fields the selected mode needs.
func (t *discoverTab) viewMenu(b *strings.Builder) {
	fmt.Fprintf(b, "%s\n\n", t.sty.big.Render("Что просканировать?"))
	for i, m := range discModes {
		marker := "  "
		name := m.name
		if discMode(i) == t.mode {
			marker = t.sty.accent.Render("▸ ")
			name = t.sty.accent.Render(name)
		}
		fmt.Fprintf(b, "%s%-24s %s\n", marker, name, t.sty.muted.Render(m.desc))
	}
	b.WriteString("\n")

	// Liveness knob: ping is on by default and finds devices that ignore TCP;
	// turning it off helps only where ICMP is blocked or rate-limited.
	state, hint := t.sty.good.Render("вкл"), "находит устройства, молчащие по TCP"
	if t.noICMP {
		state, hint = t.sty.muted.Render("выкл"), "только TCP и ARP-таблица"
	}
	fmt.Fprintf(b, "  ICMP-пинг: %s  %s  %s\n\n",
		state, t.sty.muted.Render("[i]"), t.sty.muted.Render(hint))

	switch {
	case t.editing && t.mode == modeManual:
		b.WriteString(t.cidrIn.View())
		b.WriteString("\n")
		b.WriteString(t.sty.muted.Render("Несколько сетей — через запятую. Пример: 192.168.100.0/24, 10.0.0.0/24"))
	case t.editing && t.mode == modeExpand:
		b.WriteString(t.seedIn.View())
		b.WriteString("\n")
		b.WriteString(t.commIn.View())
		b.WriteString("\n")
		b.WriteString(t.depthIn.View())
		b.WriteString("\n\n")
		b.WriteString(t.sty.muted.Render(
			"Всё можно оставить пустым — найдёт сети по traceroute.\n" +
				"SNMP-пароль (обычно public) даёт полную карту от роутеров.\n" +
				"Глубина — насколько далеко искать (2 — норм)."))
	case t.mode == modeManual || t.mode == modeExpand:
		b.WriteString(t.sty.muted.Render("Нажмите Enter, чтобы ввести параметры."))
	default:
		b.WriteString(t.sty.muted.Render("Нажмите Enter, чтобы начать."))
	}
}

// viewRunning renders live progress while a sweep is in flight.
func (t *discoverTab) viewRunning(b *strings.Builder) {
	if t.expand {
		fmt.Fprintf(b, "%s Авто-обнаружение сетей  •  найдено сетей: %d, устройств: %d\n\n",
			t.sty.accent.Render("●"), len(t.subnets), len(t.hosts))
		b.WriteString(t.tbl.View())
		return
	}
	label := "Поиск живых устройств"
	if t.phase == portscan.PhaseScan {
		label = "Проверка портов найденных устройств"
	}
	bw := max(t.w-30, 10)
	frac := 0.0
	if t.ptotal > 0 {
		frac = float64(t.pdone) / float64(t.ptotal)
	}
	fmt.Fprintf(b, "%s %s  %s %d/%d\n\n",
		t.sty.accent.Render("●"), label,
		bar(frac, bw, t.sty.accent, t.sty.muted), t.pdone, t.ptotal)
	b.WriteString(t.tbl.View())
}

// viewResults renders the finished scan: a one-line summary and the host table.
func (t *discoverTab) viewResults(b *strings.Builder) {
	if t.err != nil {
		b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		return
	}
	summary := fmt.Sprintf("Найдено устройств: %d", len(t.hosts))
	if t.expand {
		summary = fmt.Sprintf("Найдено сетей: %d, устройств: %d", len(t.subnets), len(t.hosts))
	}
	fmt.Fprintf(b, "%s\n\n", t.sty.big.Render(summary))
	b.WriteString(t.tbl.View())
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
