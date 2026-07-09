// Package tui is the full-screen Bubble Tea dashboard that fronts every
// speedtest engine. theme.go centralizes all colors and reusable styles so the
// whole look can be retuned from one place.
package tui

import "github.com/charmbracelet/lipgloss"

// Palette holds the adaptive colors used across the dashboard. AdaptiveColor
// picks the right shade for the terminal's light/dark background automatically.
type Palette struct {
	Accent    lipgloss.AdaptiveColor
	Accent2   lipgloss.AdaptiveColor
	Good      lipgloss.AdaptiveColor
	Warn      lipgloss.AdaptiveColor
	Bad       lipgloss.AdaptiveColor
	Text      lipgloss.AdaptiveColor
	Muted     lipgloss.AdaptiveColor
	Border    lipgloss.AdaptiveColor
	BorderDim lipgloss.AdaptiveColor
}

// palette is the single active palette.
var palette = Palette{
	Accent:    lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#A78BFA"},
	Accent2:   lipgloss.AdaptiveColor{Light: "#0EA5E9", Dark: "#38BDF8"},
	Good:      lipgloss.AdaptiveColor{Light: "#059669", Dark: "#34D399"},
	Warn:      lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#FBBF24"},
	Bad:       lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#F87171"},
	Text:      lipgloss.AdaptiveColor{Light: "#1F2937", Dark: "#E5E7EB"},
	Muted:     lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"},
	Border:    lipgloss.AdaptiveColor{Light: "#7C3AED", Dark: "#A78BFA"},
	BorderDim: lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#4B5563"},
}

// styles bundles the derived lipgloss styles the views reuse.
type styles struct {
	title     lipgloss.Style
	tabActive lipgloss.Style
	tabIdle   lipgloss.Style
	tabBar    lipgloss.Style
	panel     lipgloss.Style
	panelTtl  lipgloss.Style
	statusBar lipgloss.Style
	key       lipgloss.Style
	help      lipgloss.Style
	good      lipgloss.Style
	warn      lipgloss.Style
	bad       lipgloss.Style
	muted     lipgloss.Style
	accent    lipgloss.Style
	big       lipgloss.Style
}

// newStyles builds the style set from the active palette.
func newStyles() styles {
	return styles{
		title: lipgloss.NewStyle().Bold(true).Foreground(palette.Accent),
		tabActive: lipgloss.NewStyle().Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).Background(palette.Accent).
			Padding(0, 1),
		tabIdle: lipgloss.NewStyle().Foreground(palette.Muted).Padding(0, 1),
		tabBar:  lipgloss.NewStyle().Padding(0, 0, 1, 0),
		panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).BorderForeground(palette.Border).
			Padding(0, 1),
		panelTtl:  lipgloss.NewStyle().Bold(true).Foreground(palette.Accent2),
		statusBar: lipgloss.NewStyle().Foreground(palette.Muted),
		key:       lipgloss.NewStyle().Bold(true).Foreground(palette.Accent),
		help:      lipgloss.NewStyle().Foreground(palette.Muted),
		good:      lipgloss.NewStyle().Foreground(palette.Good),
		warn:      lipgloss.NewStyle().Foreground(palette.Warn),
		bad:       lipgloss.NewStyle().Foreground(palette.Bad),
		muted:     lipgloss.NewStyle().Foreground(palette.Muted),
		accent:    lipgloss.NewStyle().Foreground(palette.Accent),
		big:       lipgloss.NewStyle().Bold(true).Foreground(palette.Text),
	}
}
