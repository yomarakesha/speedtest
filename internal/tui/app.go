package tui

import (
	"fmt"
	"strings"

	"speedtest/internal/config"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// tab is one screen of the dashboard. Each engine (internet, ping, trace, ...)
// implements it. Tabs are self-contained Bubble Tea sub-models that receive the
// current content size via SetSize before View is called.
type tab interface {
	Title() string                 // short label for the tab bar
	Init() tea.Cmd                 // optional startup command
	Update(tea.Msg) (tab, tea.Cmd) // handle a message, return updated tab
	View() string                  // render at the last SetSize dimensions
	SetSize(width, height int)     // content area (inside the frame)
	ShortHelp() []string           // context key hints for the status bar
	Capturing() bool               // true when a text field wants raw keystrokes
	Busy() bool                    // true while a measurement is running
}

// model is the root Bubble Tea model: a tab bar plus the active tab's body.
type model struct {
	tabs     []tab
	active   int
	width    int
	height   int
	st       styles
	showHelp bool
}

// New builds the root dashboard model with every engine tab wired up, seeding
// the input fields from the saved config so the last-used targets are pre-filled.
func New() model {
	cfg := config.Load()
	return model{
		tabs: []tab{
			newInternetTab(),
			newLANTab(cfg.LANHost),
			newPingTab(cfg.PingHost),
			newTraceTab(cfg.TraceHost),
			newScanTab(cfg.ScanHost),
			newDiscoverTab(),
			newWiFiTab(),
			newHTTPDLTab(cfg.HTTPURL),
			newAuditTab(cfg.AuditHost),
			newHistoryTab(),
		},
		st: newStyles(),
	}
}

func (m model) Init() tea.Cmd {
	if len(m.tabs) == 0 {
		return nil
	}
	return m.tabs[m.active].Init()
}

// frameV is the vertical space the chrome (tab bar + status bar) consumes.
const frameV = 4

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeAll()
		return m, nil

	case tea.KeyMsg:
		capturing := m.tabs[m.active].Capturing()
		// Global keys that always work, even while a text field is focused.
		// Arrow keys switch tabs everywhere: in the short host/URL fields, tab
		// navigation is far more useful than in-field cursor movement.
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "tab", "ctrl+right", "right":
			m.active = (m.active + 1) % len(m.tabs)
			m.resizeActive()
			return m, m.tabs[m.active].Init()
		case "shift+tab", "ctrl+left", "left":
			m.active = (m.active - 1 + len(m.tabs)) % len(m.tabs)
			m.resizeActive()
			return m, m.tabs[m.active].Init()
		}
		// Nav shortcuts that must yield to an active text field (they are
		// printable characters that belong in the field while typing).
		if !capturing {
			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "?":
				m.showHelp = !m.showHelp
				return m, nil
			case "l":
				m.active = (m.active + 1) % len(m.tabs)
				m.resizeActive()
				return m, m.tabs[m.active].Init()
			case "h":
				m.active = (m.active - 1 + len(m.tabs)) % len(m.tabs)
				m.resizeActive()
				return m, m.tabs[m.active].Init()
			}
			if c := msg.String(); len(c) == 1 && c[0] >= '1' && c[0] <= '9' {
				if idx := int(c[0] - '1'); idx < len(m.tabs) {
					m.active = idx
					m.resizeActive()
					return m, m.tabs[m.active].Init()
				}
			}
		}
	}

	// Key messages go to the active tab only. Everything else — engine samples,
	// results, spinner ticks — is broadcast to every tab so measurements keep
	// updating in the background while the user views another tab (each tab's
	// Update ignores messages that aren't its own). This is what makes a scan or
	// trace continue while you switch away and the ● indicator stay truthful.
	if _, isKey := msg.(tea.KeyMsg); isKey {
		var cmd tea.Cmd
		m.tabs[m.active], cmd = m.tabs[m.active].Update(msg)
		return m, cmd
	}

	var cmds []tea.Cmd
	for i := range m.tabs {
		var cmd tea.Cmd
		m.tabs[i], cmd = m.tabs[i].Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return m, tea.Batch(cmds...)
}

// resizeActive tells the active tab how much room it has inside the frame.
func (m *model) resizeActive() {
	if m.width == 0 || len(m.tabs) == 0 {
		return
	}
	m.tabs[m.active].SetSize(m.width, m.height-frameV)
}

// resizeAll sizes every tab, so background tabs render correctly the moment they
// become active (their engines run regardless).
func (m *model) resizeAll() {
	if m.width == 0 {
		return
	}
	for i := range m.tabs {
		m.tabs[i].SetSize(m.width, m.height-frameV)
	}
}

func (m model) View() string {
	if m.width == 0 {
		return "загрузка..."
	}
	if m.showHelp {
		return lipgloss.JoinVertical(lipgloss.Left,
			m.tabBar(),
			m.helpOverlay(),
			m.statusBar(),
		)
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.tabBar(),
		m.tabs[m.active].View(),
		m.statusBar(),
	)
}

// helpOverlay is a centered card listing global keys, every tab, and the active
// tab's own shortcuts. Toggled with "?".
func (m model) helpOverlay() string {
	var b strings.Builder
	b.WriteString(m.st.title.Render("Справка"))
	b.WriteString("\n\n")
	b.WriteString(m.st.big.Render("Навигация"))
	b.WriteString("\n")
	for _, l := range []string{
		"Tab / Shift+Tab — следующая / предыдущая вкладка",
		"1-8 — быстрый переход к вкладке",
		"← → или h l — переключение вкладок",
		"? — показать/скрыть эту справку",
		"q или Ctrl+C — выход",
	} {
		fmt.Fprintf(&b, "  %s\n", l)
	}

	b.WriteString("\n")
	b.WriteString(m.st.big.Render("Вкладки"))
	b.WriteString("\n")
	for i, t := range m.tabs {
		fmt.Fprintf(&b, "  %s %s\n", m.st.key.Render(fmt.Sprintf("%d", i+1)), t.Title())
	}

	if h := m.tabs[m.active].ShortHelp(); len(h) > 0 {
		b.WriteString("\n")
		b.WriteString(m.st.big.Render("Текущая вкладка: " + m.tabs[m.active].Title()))
		b.WriteString("\n")
		for _, l := range h {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}

	card := m.st.panel.Render(b.String())
	return lipgloss.Place(m.width, m.height-frameV, lipgloss.Center, lipgloss.Center, card)
}

func (m model) tabBar() string {
	cells := make([]string, len(m.tabs))
	for i, t := range m.tabs {
		label := t.Title()
		if t.Busy() {
			label = "●" + label // running measurement, visible from any tab
		}
		if i == m.active {
			cells[i] = m.st.tabActive.Render(label)
		} else {
			cells[i] = m.st.tabIdle.Render(label)
		}
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
	brand := m.st.title.Render("⚡ speedtest")
	gap := max(m.width-lipgloss.Width(bar)-lipgloss.Width(brand), 1)
	return m.st.tabBar.Render(bar + strings.Repeat(" ", gap) + brand)
}

func (m model) statusBar() string {
	if m.showHelp {
		return m.st.statusBar.Render("[?] закрыть справку   [q] выход")
	}
	hints := []string{"[Tab] вкладки", "[1-8] переход"}
	if h := m.tabs[m.active].ShortHelp(); len(h) > 0 {
		hints = append(hints, h...)
	}
	hints = append(hints, "[?] справка", "[q] выход")
	return m.st.statusBar.Render(strings.Join(hints, "   "))
}
