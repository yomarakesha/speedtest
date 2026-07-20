package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubProbe returns a fixed result for orchestration tests.
type stubProbe struct {
	name   string
	alerts []Alert
	err    error
}

func (s stubProbe) Name() string            { return s.name }
func (s stubProbe) Target() string          { return "t" }
func (s stubProbe) Interval() time.Duration { return time.Hour }
func (s stubProbe) Run(context.Context) Result {
	return Result{Check: s.name, Target: "t", Err: s.err, Alerts: s.alerts}
}

// captureSink records delivered alerts and can be made to fail. It is
// mutex-guarded so it is safe when Run delivers from concurrent probe goroutines.
type captureSink struct {
	mu   sync.Mutex
	got  []Alert
	fail bool
}

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Deliver(a Alert) error {
	if c.fail {
		return errors.New("boom")
	}
	c.mu.Lock()
	c.got = append(c.got, a)
	c.mu.Unlock()
	return nil
}
func (c *captureSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func TestCheckReportsBreachAndFansOut(t *testing.T) {
	cap := &captureSink{}
	probes := []Probe{
		stubProbe{name: "ping", alerts: []Alert{{Check: "ping", Title: "bad"}}},
		stubProbe{name: "clean"},
	}
	d := NewDispatcher(cap)
	if !Check(context.Background(), probes, d) {
		t.Error("expected breached=true")
	}
	if len(cap.got) != 1 || cap.got[0].Title != "bad" {
		t.Errorf("sink should get the one alert, got %+v", cap.got)
	}
}

func TestCheckNoBreach(t *testing.T) {
	d := NewDispatcher(&captureSink{})
	if Check(context.Background(), []Probe{stubProbe{name: "clean"}}, d) {
		t.Error("expected breached=false")
	}
}

func TestDispatcherToleratesSinkError(t *testing.T) {
	good := &captureSink{}
	bad := &captureSink{fail: true}
	d := NewDispatcher(bad, good)
	d.Deliver(Alert{Title: "x"}) // must not panic; good sink still gets it
	if len(good.got) != 1 {
		t.Errorf("good sink should still receive alert despite bad sink error")
	}
}

func TestRunFiresEachProbeAndStopsOnCancel(t *testing.T) {
	cap := &captureSink{}
	probes := []Probe{
		stubProbe{name: "a", alerts: []Alert{{Check: "a", Title: "1"}}},
		stubProbe{name: "b", alerts: []Alert{{Check: "b", Title: "2"}}},
		stubProbe{name: "c", alerts: []Alert{{Check: "c", Title: "3"}}},
	}
	d := NewDispatcher(cap)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { Run(ctx, probes, d); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
	// Each probe fires once immediately (interval is 1h), so exactly 3 alerts.
	if cap.count() != 3 {
		t.Errorf("want 3 alerts from immediate fire, got %d", cap.count())
	}
}

func TestStdoutSink(t *testing.T) {
	var buf bytes.Buffer
	s := &stdoutSink{w: &buf}
	if err := s.Deliver(Alert{Time: time.Now(), Check: "ping", Target: "h", Severity: SevWarn, Title: "slow"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ping/h")) || !bytes.Contains(buf.Bytes(), []byte("slow")) {
		t.Errorf("stdout line missing content: %q", buf.String())
	}
}

func TestWebhookSink(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := &webhookSink{url: srv.URL, client: srv.Client()}
	if err := s.Deliver(Alert{Check: "ping", Target: "h", Title: "slow"}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if _, ok := got["text"]; !ok {
		t.Errorf("webhook payload missing text field: %+v", got)
	}
	if _, ok := got["alert"]; !ok {
		t.Errorf("webhook payload missing alert field: %+v", got)
	}
}

func TestWebhookSinkErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := &webhookSink{url: srv.URL, client: srv.Client()}
	if err := s.Deliver(Alert{Title: "x"}); err == nil {
		t.Error("expected error on 500 status")
	}
}

func TestBuildSinks(t *testing.T) {
	sinks := BuildSinks(SinkConfig{Stdout: true, Webhook: "http://x", Desktop: true, History: true}, &bytes.Buffer{})
	if len(sinks) != 4 {
		t.Errorf("want 4 sinks, got %d", len(sinks))
	}
	none := BuildSinks(SinkConfig{}, &bytes.Buffer{})
	if len(none) != 0 {
		t.Errorf("want 0 sinks, got %d", len(none))
	}
}
