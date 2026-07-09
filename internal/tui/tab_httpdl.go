package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"speedtest/internal/history"
	"speedtest/internal/util"
	"speedtest/internal/webspeed"

	"github.com/NimbleMarkets/ntcharts/sparkline"
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

// httpdlTab tests download speed from any HTTP(S) URL — no agent needed on the
// other side (router firmware page, NAS file, CDN object, ...).
type httpdlTab struct {
	sty   styles
	input textinput.Model
	spin  spinner.Model
	sl    sparkline.Model
	w, h  int
	ch    chan tea.Msg
	stop  context.CancelFunc

	running bool
	done    bool
	cur     float64
	peak    float64
	res     webspeed.Result
	err     error
}

func newHTTPDLTab() tab {
	s := newStyles()
	ti := textinput.New()
	ti.Placeholder = "192.168.1.1/big.bin или https://host/file"
	ti.CharLimit = 500
	ti.Prompt = "URL: "
	ti.Focus()
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = s.accent
	return &httpdlTab{
		sty: s, input: ti, spin: sp,
		sl: sparkline.New(10, 3, sparkline.WithMaxValue(100), sparkline.WithStyle(s.good)),
	}
}

func (t *httpdlTab) Title() string { return "HTTP" }
func (t *httpdlTab) Init() tea.Cmd { return textinput.Blink }

func (t *httpdlTab) ShortHelp() []string {
	return []string{"[Enter] старт/стоп", "тест до 15 секунд"}
}

func (t *httpdlTab) Capturing() bool { return t.input.Focused() }

func (t *httpdlTab) SetSize(w, h int) {
	t.w, t.h = w, h
	cw, ch := t.chartSize()
	t.sl.Resize(cw, ch)
}

func (t *httpdlTab) chartSize() (int, int) {
	cw := t.w - 6
	if cw < 10 {
		cw = 10
	}
	ch := t.h - 8
	if ch < 3 {
		ch = 3
	}
	return cw, ch
}

func (t *httpdlTab) start() tea.Cmd {
	url := strings.TrimSpace(t.input.Value())
	if url == "" {
		return nil
	}
	cw, ch := t.chartSize()
	t.sl = sparkline.New(cw, ch, sparkline.WithMaxValue(100), sparkline.WithStyle(t.sty.good))
	t.running, t.done = true, false
	t.cur, t.peak = 0, 0
	t.res, t.err = webspeed.Result{}, nil
	t.input.Blur()

	ctx, cancel := context.WithCancel(context.Background())
	t.stop = cancel
	ch2 := make(chan tea.Msg, 64)
	t.ch = ch2
	go func() {
		res, err := webspeed.Download(ctx, url, 15*time.Second, func(mbps float64) {
			ch2 <- httpSampleMsg{mbps}
		})
		ch2 <- httpResultMsg{res, err}
	}()
	return tea.Batch(listen(ch2), t.spin.Tick)
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
			var cmd tea.Cmd
			t.spin, cmd = t.spin.Update(msg)
			return t, cmd
		}
		return t, nil

	case httpSampleMsg:
		t.cur = msg.mbps
		if msg.mbps > t.peak {
			t.peak = msg.mbps
		}
		pushScaledSpark(&t.sl, msg.mbps, t.peak)
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
		fmt.Fprintf(&b, "%s Скачивание: %s   пик %s\n",
			t.spin.View(), t.sty.big.Render(fmtMbps(t.cur)), fmtMbps(t.peak))
		b.WriteString(t.sl.View())
	case t.done:
		if t.err != nil {
			b.WriteString(t.sty.bad.Render("Ошибка: " + t.err.Error()))
		} else {
			line := fmt.Sprintf("Скорость %s   объём %s   время %.1f с",
				t.sty.good.Render(fmtMbps(t.res.DownloadMbps)),
				util.Bytes(t.res.Bytes), t.res.Seconds)
			if !t.res.Reliable {
				line += "   " + t.sty.warn.Render("(файл мал — оценка неточная)")
			}
			b.WriteString(line)
			b.WriteString("\n")
			b.WriteString(t.sl.View())
		}
	default:
		b.WriteString(t.sty.muted.Render("Download-тест по любому HTTP(S)-адресу — агент на устройстве не нужен.\nПодойдёт большой файл: прошивка на роутере, файл на NAS, объект CDN."))
	}
	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("HTTP download-тест", t.w, t.h, b.String()))
}
