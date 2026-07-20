package tui

import (
	"context"
	"fmt"
	"strings"

	"speedtest/internal/config"
	"speedtest/internal/history"
	"speedtest/internal/util"
	"speedtest/internal/webspeed"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// httpSampleMsg carries one instantaneous throughput sample.
type httpSampleMsg struct{ mbps float64 }

// httpResultMsg carries the final download result.
type httpResultMsg struct {
	res webspeed.Result
	err error
}

// httpReserveV is the vertical space above the graph (input + status rows).
const httpReserveV = 5

// httpdlTab tests download speed from any HTTP(S) URL — no agent needed on the
// other side (router firmware page, NAS file, CDN object, camera stream, ...).
type httpdlTab struct {
	sty   styles
	input textinput.Model
	m     meter
	w, h  int
	ch    chan tea.Msg
	stop  context.CancelFunc

	running bool
	done    bool
	res     webspeed.Result
	err     error
}

func newHTTPDLTab(seed string) tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "http://admin:pass@192.168.1.64/Streaming/channels/1/httpPreview"
	ti.CharLimit = 500
	ti.Prompt = "URL: "
	ti.SetValue(seed)
	ti.Focus()
	return &httpdlTab{sty: s, input: ti, m: newMeter(s, false)}
}

func (t *httpdlTab) Title() string { return "HTTP" }
func (t *httpdlTab) Init() tea.Cmd { return textinput.Blink }
func (t *httpdlTab) Busy() bool    { return t.running }

func (t *httpdlTab) ShortHelp() []string {
	return []string{"[Enter] старт/стоп", "тест до 15 секунд"}
}

func (t *httpdlTab) Capturing() bool { return t.input.Focused() }

func (t *httpdlTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.m.setSize(w, h, httpReserveV)
}

func (t *httpdlTab) start() tea.Cmd {
	url := strings.TrimSpace(t.input.Value())
	if url == "" {
		return nil
	}
	config.Remember("httpdl", url)
	t.m.reset()
	t.running, t.done = true, false
	t.res, t.err = webspeed.Result{}, nil
	t.input.Blur()

	ctx, cancel := context.WithCancel(context.Background())
	t.stop = cancel
	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := webspeed.Download(ctx, url, httpdlDuration, func(mbps float64) {
			ch2 <- httpSampleMsg{mbps}
		})
		ch2 <- httpResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.m.spin.Tick)
}

func (t *httpdlTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "enter" {
			if t.running {
				if t.stop != nil {
					t.stop()
				}
				return t, nil
			}
			return t, t.start()
		}

	case spinner.TickMsg:
		if t.running {
			return t, t.m.tick(msg)
		}
		return t, nil

	case httpSampleMsg:
		t.m.pushDown(msg.mbps)
		return t, listen(t.ch)

	case httpResultMsg:
		t.running, t.done = false, true
		t.res, t.err = msg.res, msg.err
		if t.err == nil {
			_ = history.Append(history.Record{
				Kind:         history.KindHTTPDL,
				Target:       t.res.URL,
				DownloadMbps: t.res.DownloadMbps,
			})
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

func (t *httpdlTab) View() string {
	var b strings.Builder
	b.WriteString(t.input.View())
	b.WriteString("\n")

	switch {
	case t.running:
		fmt.Fprintf(&b, "%s Скачивание...\n", t.m.spin.View())
		b.WriteString(t.m.charts("↓ приём", ""))
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			fmt.Fprintf(&b, "Скорость %s   объём %s   время %.1f с",
				t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
				util.Bytes(t.res.Bytes), t.res.Seconds)
			if !t.res.Reliable {
				b.WriteString("   ")
				b.WriteString(t.sty.warn.Render("(данных мало — оценка неточная)"))
			}
			b.WriteString("\n")
			b.WriteString(t.m.charts("↓ приём", ""))
		}
	default:
		if hint := urlHint(t.sty, t.input.Value()); hint != "" {
			b.WriteString(hint)
			b.WriteString("\n")
		}
		b.WriteString(t.sty.muted.Render(
			"Download-тест по любому HTTP(S)-адресу — агент на устройстве не нужен.\n" +
				"Годится: большой файл (прошивка/NAS/CDN), MJPEG-поток или snapshot камеры.\n" +
				"Мелкий ответ (снапшот) тянется повторно всё окно — счёт устойчивый.\n" +
				"Логин к камере — прямо в URL: http://admin:pass@IP/путь"))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("HTTP download-тест", t.w, t.h, b.String()))
}
