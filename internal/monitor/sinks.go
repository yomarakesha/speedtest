package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"speedtest/internal/history"
)

// BuildSinks turns a SinkConfig into the enabled sinks. out is where the stdout
// sink writes (injected for tests); pass os.Stdout in production.
func BuildSinks(cfg SinkConfig, out io.Writer) []Sink {
	var sinks []Sink
	if cfg.Stdout {
		sinks = append(sinks, &stdoutSink{w: out})
	}
	if cfg.Webhook != "" {
		sinks = append(sinks, &webhookSink{url: cfg.Webhook, client: &http.Client{Timeout: 10 * time.Second}})
	}
	if cfg.Desktop {
		sinks = append(sinks, &desktopSink{})
	}
	if cfg.History {
		sinks = append(sinks, &historySink{})
	}
	return sinks
}

// --- stdout ----------------------------------------------------------------

type stdoutSink struct{ w io.Writer }

func (s *stdoutSink) Name() string { return "stdout" }
func (s *stdoutSink) Deliver(a Alert) error {
	_, err := fmt.Fprintln(s.w, a.String())
	return err
}

// --- webhook ---------------------------------------------------------------

type webhookSink struct {
	url    string
	client *http.Client
}

func (s *webhookSink) Name() string { return "webhook" }

// Deliver POSTs the alert as JSON. A "text" field carries a human summary so
// Slack/Discord incoming webhooks render it out of the box; the full alert is
// included alongside for richer consumers.
func (s *webhookSink) Deliver(a Alert) error {
	payload := struct {
		Text  string `json:"text"`
		Alert Alert  `json:"alert"`
	}{Text: a.String(), Alert: a}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := s.client.Post(s.url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook вернул статус %d", resp.StatusCode)
	}
	return nil
}

// --- desktop notification --------------------------------------------------

type desktopSink struct{}

func (s *desktopSink) Name() string { return "desktop" }

// Deliver shows an OS toast/notification by shelling out to the platform's
// native tool — no third-party dependency. A missing tool degrades to an error
// that the dispatcher logs; it never stops monitoring.
func (s *desktopSink) Deliver(a Alert) error {
	title := fmt.Sprintf("speedtest: %s/%s", a.Check, a.Target)
	body := a.Title
	if a.Detail != "" {
		body += " — " + a.Detail
	}
	switch runtime.GOOS {
	case "windows":
		// Windows toast via PowerShell + the Windows.UI.Notifications API.
		ps := fmt.Sprintf(`
$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x=$t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode(%q)) > $null
$x.Item(1).AppendChild($t.CreateTextNode(%q)) > $null
$n=[Windows.UI.Notifications.ToastNotification]::new($t)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('speedtest').Show($n)`, title, body)
		return exec.Command("powershell", "-NoProfile", "-Command", ps).Run()
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q", body, title)
		return exec.Command("osascript", "-e", script).Run()
	case "linux":
		return exec.Command("notify-send", title, body).Run()
	default:
		return fmt.Errorf("десктоп-уведомления не поддержаны на %s", runtime.GOOS)
	}
}

// --- history ---------------------------------------------------------------

type historySink struct{}

func (s *historySink) Name() string { return "history" }

// Deliver appends the alert to the shared measurement history as a monitor
// record, so breaches show up in `speedtest history` and its exports.
func (s *historySink) Deliver(a Alert) error {
	note := a.Severity + ": " + a.Title
	if a.Detail != "" {
		note += " (" + a.Detail + ")"
	}
	return history.Append(history.Record{
		Time:   a.Time,
		Kind:   history.KindMonitor,
		Target: fmt.Sprintf("%s/%s", a.Check, a.Target),
		Note:   note,
	})
}
