package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/netinfo"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// infoResultMsg carries the finished network info snapshot.
type infoResultMsg struct{ res netinfo.Result }

// infoTab shows external IP/ISP, local interfaces, default gateway, DNS
// servers and IPv6 support. It gathers automatically when the tab opens.
type infoTab struct {
	sty  styles
	spin spinner.Model
	w, h int
	ch   chan tea.Msg

	loading bool
	loaded  bool
	res     netinfo.Result
}

func newInfoTab() tab {
	s := newStyles()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &infoTab{sty: s, spin: sp}
}

func (t *infoTab) Title() string { return "Инфо" }

func (t *infoTab) Init() tea.Cmd {
	if t.loaded || t.loading {
		return nil
	}
	t.loading = true

	ch := make(chan tea.Msg, 1)
	t.ch = ch
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ch <- infoResultMsg{netinfo.Gather(ctx)}
	}()
	return tea.Batch(listen(ch), t.spin.Tick)
}

func (t *infoTab) ShortHelp() []string { return nil }
func (t *infoTab) Capturing() bool     { return false }
func (t *infoTab) SetSize(w, h int)    { t.w, t.h = w, h }

func (t *infoTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if t.loading {
			var cmd tea.Cmd
			t.spin, cmd = t.spin.Update(msg)
			return t, cmd
		}
		return t, nil

	case infoResultMsg:
		t.loading, t.loaded = false, true
		t.res = msg.res
		return t, nil
	}
	return t, nil
}

func (t *infoTab) View() string {
	var b strings.Builder

	switch {
	case t.loading:
		fmt.Fprintf(&b, "%s Собираю данные о сети...\n", t.spin.View())
	case t.loaded:
		b.WriteString(t.summary())
	default:
		b.WriteString(t.sty.muted.Render("Загрузка..."))
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Информация о сети", t.w, t.h, b.String()))
}

func (t *infoTab) summary() string {
	r := t.res
	var b strings.Builder

	b.WriteString(t.sty.big.Render("Внешний IP"))
	b.WriteString("\n")
	if r.ExternalErr != "" {
		fmt.Fprintf(&b, "  недоступно: %s\n", r.ExternalErr)
	} else {
		fmt.Fprintf(&b, "  %s  (%s, %s, %s)\n", r.ExternalIP, r.ISP, r.City, r.Country)
	}

	b.WriteString("\n")
	b.WriteString(t.sty.big.Render("Локальные интерфейсы"))
	b.WriteString("\n")
	if len(r.Interfaces) == 0 {
		b.WriteString("  не найдено\n")
	}
	for _, i := range r.Interfaces {
		fmt.Fprintf(&b, "  %-12s MAC %-17s IP %s\n", i.Name, i.MAC, strings.Join(i.IPs, ", "))
	}

	b.WriteString("\n")
	b.WriteString(t.sty.big.Render("Шлюз по умолчанию"))
	b.WriteString("\n")
	if r.GatewayErr != "" {
		fmt.Fprintf(&b, "  недоступно: %s\n", r.GatewayErr)
	} else {
		fmt.Fprintf(&b, "  %s\n", r.Gateway)
	}

	b.WriteString("\n")
	b.WriteString(t.sty.big.Render("DNS-серверы"))
	b.WriteString("\n")
	if r.DNSErr != "" {
		fmt.Fprintf(&b, "  недоступно: %s\n", r.DNSErr)
	} else if len(r.DNSServers) == 0 {
		b.WriteString("  не найдено\n")
	} else {
		fmt.Fprintf(&b, "  %s\n", strings.Join(r.DNSServers, ", "))
	}

	b.WriteString("\n")
	b.WriteString(t.sty.big.Render("IPv6"))
	b.WriteString("\n")
	if r.IPv6 {
		b.WriteString("  " + t.sty.good.Render("поддерживается") + "\n")
	} else {
		b.WriteString("  " + t.sty.muted.Render("не обнаружен") + "\n")
	}

	return b.String()
}
