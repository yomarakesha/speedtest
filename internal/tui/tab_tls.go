package tui

import (
	"fmt"
	"strings"
	"time"

	"speedtest/internal/tlsinfo"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tlsResultMsg carries the outcome of a certificate inspection.
type tlsResultMsg struct {
	res tlsinfo.Result
	err error
}

// tlsTab inspects the TLS certificate a server presents.
type tlsTab struct {
	sty   styles
	input textinput.Model
	spin  spinner.Model
	w, h  int
	ch    chan tea.Msg

	running bool
	done    bool
	res     tlsinfo.Result
	err     error
}

func newTLSTab() tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "example.com или example.com:8443"
	ti.CharLimit = 253
	ti.Prompt = "Хост: "
	ti.Focus()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &tlsTab{sty: s, input: ti, spin: sp}
}

func (t *tlsTab) Title() string { return "TLS" }
func (t *tlsTab) Init() tea.Cmd { return textinput.Blink }

func (t *tlsTab) ShortHelp() []string {
	return []string{"[Enter] проверить сертификат"}
}

func (t *tlsTab) Capturing() bool  { return t.input.Focused() }
func (t *tlsTab) SetSize(w, h int) { t.w, t.h = w, h }

func (t *tlsTab) start() tea.Cmd {
	host := strings.TrimSpace(t.input.Value())
	if host == "" {
		return nil
	}
	t.running, t.done = true, false
	t.res, t.err = tlsinfo.Result{}, nil
	t.input.Blur()

	ch := make(chan tea.Msg, 1)
	t.ch = ch
	go func() {
		res, err := tlsinfo.Inspect(host, 5*time.Second)
		ch <- tlsResultMsg{res, err}
	}()
	return tea.Batch(listen(ch), t.spin.Tick)
}

func (t *tlsTab) Update(msg tea.Msg) (tab, tea.Cmd) {
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

	case tlsResultMsg:
		t.running, t.done = false, true
		t.res, t.err = msg.res, msg.err
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

func (t *tlsTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.running:
		fmt.Fprintf(&b, "%s Подключение...\n", t.spin.View())
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			b.WriteString(t.certView())
		}
	default:
		b.WriteString(t.sty.muted.Render("Проверка TLS-сертификата: издатель, субъект, срок действия,\nверсия TLS, шифр, SAN-имена, время рукопожатия."))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("TLS-сертификат", t.w, t.h, b.String()))
}

func (t *tlsTab) certView() string {
	r := t.res
	var b strings.Builder
	fmt.Fprintf(&b, "Издатель:    %s\n", r.Issuer)
	fmt.Fprintf(&b, "Субъект:     %s\n", r.Subject)
	fmt.Fprintf(&b, "Действителен: %s — %s\n", r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
	if r.Expired {
		b.WriteString(t.sty.bad.Render("⚠ Срок действия истёк") + "\n")
	}
	fmt.Fprintf(&b, "Версия TLS:  %s\n", r.Version)
	fmt.Fprintf(&b, "Шифр:        %s\n", r.CipherSuite)
	if len(r.SANs) > 0 {
		fmt.Fprintf(&b, "SAN-имена:   %s\n", strings.Join(r.SANs, ", "))
	}
	fmt.Fprintf(&b, "Рукопожатие: %.1f мс\n", r.HandshakeMs)
	if r.VerifyError != "" {
		b.WriteString(t.sty.warn.Render("⚠ Цепочка доверия: " + r.VerifyError))
	} else {
		b.WriteString(t.sty.good.Render("Цепочка доверия: действительна"))
	}
	return b.String()
}

func (t *tlsTab) Busy() bool { return t.running }
