package tui

import (
	"fmt"
	"strings"

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

// New builds the root dashboard model with every engine tab wired up.
func New() model {
	return model{
		tabs: []tab{
			newInternetTab(),
			newLANTab(),
			newPingTab(),
			newTraceTab(),
			newScanTab(),
			newDiscoverTab(),
			newHTTPDLTab(),
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
		m.resizeActive()
		return m, nil

	case tea.KeyMsg:
		capturing := m.tabs[m.active].Capturing()
		// Global keys that always work, even while a text field is focused.
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "tab", "ctrl+right":
			m.active = (m.active + 1) % len(m.tabs)
			m.resizeActive()
			return m, m.tabs[m.active].Init()
		case "shift+tab", "ctrl+left":
			m.active = (m.active - 1 + len(m.tabs)) % len(m.tabs)
			m.resizeActive()
			return m, m.tabs[m.active].Init()
		}
		// Nav shortcuts that must yield to an active text field.
		if !capturing {
			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "?":
				m.showHelp = !m.showHelp
				return m, nil
			case "right", "l":
				m.active = (m.active + 1) % len(m.tabs)
				m.resizeActive()
				return m, m.tabs[m.active].Init()
			case "left", "h":
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

	// Forward everything else to the active tab.
	var cmd tea.Cmd
	m.tabs[m.active], cmd = m.tabs[m.active].Update(msg)
	return m, cmd
}

// resizeActive tells the active tab how much room it has inside the frame.
func (m *model) resizeActive() {
	if m.width == 0 || len(m.tabs) == 0 {
		return
	}
	m.tabs[m.active].SetSize(m.width, m.height-frameV)
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
		b.WriteString("  " + l + "\n")
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
			b.WriteString("  " + l + "\n")
		}
	}

	card := m.st.panel.Render(b.String())
	return lipgloss.Place(m.width, m.height-frameV, lipgloss.Center, lipgloss.Center, card)
}

func (m model) tabBar() string {
	cells := make([]string, len(m.tabs))
	for i, t := range m.tabs {
		label := t.Title()
		if i == m.active {
			cells[i] = m.st.tabActive.Render(label)
		} else {
			cells[i] = m.st.tabIdle.Render(label)
		}
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
	brand := m.st.title.Render("⚡ speedtest")
	gap := m.width - lipgloss.Width(bar) - lipgloss.Width(brand)
	if gap < 1 {
		gap = 1
	}
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
