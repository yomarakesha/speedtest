package tui

import (
	"fmt"
	"strings"

	"speedtest/internal/audit"
	"speedtest/internal/config"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// auditFindingMsg carries one finding as it is produced; auditDoneMsg closes
// the run and carries the overall grade.
type auditFindingMsg struct{ f audit.Finding }
type auditDoneMsg struct{ grade string }

// auditTab runs the TLS and HTTP security audits against one host and shows the
// findings live, coloured by severity, with an overall A–F grade.
type auditTab struct {
	sty   styles
	input textinput.Model
	w, h  int
	ch    chan tea.Msg

	running  bool
	done     bool
	host     string
	grade    string
	findings []audit.Finding
}

func newAuditTab(seed string) tab {
	ti := textinput.New()
	ti.Placeholder = "example.com"
	ti.CharLimit = 253
	ti.Prompt = "Хост: "
	ti.SetValue(seed)
	ti.Focus()
	return &auditTab{sty: newStyles(), input: ti}
}

func (t *auditTab) Title() string    { return "Аудит" }
func (t *auditTab) Init() tea.Cmd    { return textinput.Blink }
func (t *auditTab) Busy() bool       { return t.running }
func (t *auditTab) Capturing() bool  { return t.input.Focused() }
func (t *auditTab) SetSize(w, h int) { t.w, t.h = w, h }
func (t *auditTab) ShortHelp() []string {
	return []string{"[Enter] аудит TLS + HTTP-заголовков"}
}

func (t *auditTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	config.Remember("audit", host)
	t.host = host
	t.running, t.done = true, false
	t.findings = nil
	t.grade = ""
	t.input.Blur()

	ch := make(chan tea.Msg, 64)
	t.ch = ch
	go func() {
		// Same orchestration and timeouts the CLI uses, so a host grades
		// identically in both. Passive checks only — the intrusive/DNS checks
		// need an authorization flag the TUI can't collect.
		all := audit.RunChecks(host, audit.DefaultAuditOptions(),
			func(f audit.Finding) { ch <- auditFindingMsg{f} }, nil)
		report := audit.NewReport(host, all)
		audit.Record(report)
		ch <- auditDoneMsg{report.Grade}
	}()
	return listen(ch)
}

func (t *auditTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" && !t.running {
			return t, t.start()
		}

	case auditFindingMsg:
		t.findings = append(t.findings, msg.f)
		return t, listen(t.ch)

	case auditDoneMsg:
		t.running, t.done = false, true
		t.grade = msg.grade
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

func (t *auditTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.running:
		fmt.Fprintf(&b, "\n%s%s ...\n", t.sty.accent.Render("● проверяю "), t.host)
		b.WriteString(t.findingList())
	case t.done:
		fmt.Fprintf(&b, "\n%s\n", t.gradeLine())
		b.WriteString(t.findingList())
	default:
		if hint := hostHint(t.sty, t.input.Value()); hint != "" {
			b.WriteString(hint)
		} else {
			b.WriteString(t.sty.muted.Render(
				"Аудит TLS (сертификат, версии протокола) и HTTP-заголовков безопасности."))
		}
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Аудит безопасности", t.w, t.h, b.String()))
}

// gradeLine renders the overall grade, coloured by how good it is.
func (t *auditTab) gradeLine() string {
	style := t.sty.good
	switch t.grade {
	case "D", "F":
		style = t.sty.bad
	case "C":
		style = t.sty.warn
	}
	return t.sty.big.Render("Оценка: ") +
		style.Render(t.grade) +
		t.sty.muted.Render(fmt.Sprintf("   (находок: %d)", len(t.findings)))
}

func (t *auditTab) findingList() string {
	if len(t.findings) == 0 {
		if t.done {
			return "\n" + t.sty.good.Render("Проблем не обнаружено.")
		}
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, f := range t.findings {
		fmt.Fprintf(&b, "  %s  %s\n",
			t.sevBadge(f.Severity),
			t.sty.muted.Render(f.Title))
	}
	return b.String()
}

// sevBadge renders a fixed-width, coloured severity label.
func (t *auditTab) sevBadge(s audit.Severity) string {
	label := fmt.Sprintf("%-9s", s.String())
	switch s {
	case audit.Critical, audit.High:
		return t.sty.bad.Render(label)
	case audit.Medium:
		return t.sty.warn.Render(label)
	case audit.Low:
		return t.sty.accent.Render(label)
	default:
		return t.sty.muted.Render(label)
	}
}
