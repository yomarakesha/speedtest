package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"speedtest/internal/orchclient"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// orchPollBufferSize must fit every message the bounded post-submit poll loop
// in startPolling can send even if nobody is listening anymore (the tab moved
// on to a fresh refresh/poll and abandoned this channel) — otherwise a late
// send blocks that goroutine forever instead of letting it exit.
const orchPollBufferSize = 100

// orchView is which of the tab's three screens is showing.
type orchView int

const (
	orchViewForm   orchView = iota // CIDR input focused; Enter submits a new job
	orchViewList                   // job history table focused
	orchViewDetail                 // one job's per-host results
)

type orchHealthMsg struct {
	ch                         chan tea.Msg
	orchOK, auditOK, scanOK    bool
	orchErr, auditErr, scanErr string
}

type orchJobsMsg struct {
	ch   chan tea.Msg
	jobs []orchclient.JobSummary
	err  error
}

type orchPollDoneMsg struct{ ch chan tea.Msg }

type orchJobPollMsg struct {
	ch    chan tea.Msg
	jobID string
	job   orchclient.Job
	err   error
}

type orchSubmitMsg struct {
	jobID string
	err   error
}

type orchDetailMsg struct {
	jobID string
	job   orchclient.Job
	err   error
}

// orchestratorTab drives the Python orchestrator (and, for the health strip,
// audit-svc/scan-svc directly) over HTTP: submit a discover-and-audit job,
// watch the job history it accumulates, and drill into one job's per-host
// findings — the same pipeline that feeds Wazuh, from inside the terminal.
type orchestratorTab struct {
	sty  styles
	w, h int
	cfg  orchclient.Config

	view orchView

	cidrIn textinput.Model

	ch chan tea.Msg // channel backing whichever background fetch is in flight

	healthChecked                 bool
	orchOK, auditOK, scanOK       bool
	orchErrS, auditErrS, scanErrS string

	jobs    []orchclient.JobSummary
	jobsTbl table.Model
	jobsErr error
	polling bool

	status string

	detail    *orchclient.Job
	detailID  string
	detailErr error
	hostsTbl  table.Model
}

func newOrchestratorTab() tab {
	ti := textinput.New()
	ti.Prompt = "CIDR: "
	ti.Placeholder = "192.168.1.0/24"
	ti.CharLimit = 128
	ti.Focus()
	return &orchestratorTab{
		sty:      newStyles(),
		cfg:      orchclient.DefaultConfig(),
		cidrIn:   ti,
		jobsTbl:  newTable(orchJobsColumns(80), 8),
		hostsTbl: newTable(orchHostsColumns(80), 8),
	}
}

func (t *orchestratorTab) Title() string { return "Оркестратор" }

// Init is called on every tab activation (including switching back to this
// tab), not just the first. If a submitted job is still being polled,
// refresh() would reset polling=false and swap t.ch out from under the
// running startPolling goroutine, silently dropping its progress updates.
func (t *orchestratorTab) Init() tea.Cmd {
	if t.polling {
		return nil
	}
	return t.refresh()
}
func (t *orchestratorTab) Busy() bool { return t.polling }
func (t *orchestratorTab) Capturing() bool {
	return t.view == orchViewForm && t.cidrIn.Focused()
}

func (t *orchestratorTab) ShortHelp() []string {
	switch t.view {
	case orchViewList:
		return []string{"[↑/↓] прокрутка", "[Enter] детали", "[r] обновить", "[Esc/n] новая задача"}
	case orchViewDetail:
		return []string{"[↑/↓] хост", "[r] обновить", "[Esc] назад к списку"}
	default:
		return []string{"[Enter] discover+audit по CIDR", "[Esc] список задач"}
	}
}

func (t *orchestratorTab) SetSize(w, h int) {
	t.w, t.h = w, h
	t.jobsTbl.SetColumns(orchJobsColumns(w))
	t.jobsTbl.SetHeight(max(h-9, 3))
	t.hostsTbl.SetColumns(orchHostsColumns(w))
	t.hostsTbl.SetHeight(max(h-12, 3))
}

// refresh re-checks all three services' /healthz and reloads the job list —
// used on tab entry and by [r]. It supersedes any in-flight poll: pressing r
// mid-poll gives up on tracking that job's fine-grained progress in favor of
// an immediate, complete picture.
func (t *orchestratorTab) refresh() tea.Cmd {
	t.polling = false
	cfg := t.cfg
	ch := make(chan tea.Msg, 4)
	t.ch = ch
	go func() {
		hm := orchHealthMsg{ch: ch}
		var wg sync.WaitGroup
		check := func(url string, ok *bool, errS *string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := orchclient.Healthz(ctx, url); err != nil {
				*errS = err.Error()
			} else {
				*ok = true
			}
		}
		wg.Add(3)
		go check(cfg.OrchestratorURL, &hm.orchOK, &hm.orchErr)
		go check(cfg.AuditSvcURL, &hm.auditOK, &hm.auditErr)
		go check(cfg.ScanSvcURL, &hm.scanOK, &hm.scanErr)
		wg.Wait()
		ch <- hm

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		jobs, err := orchclient.ListJobs(ctx, cfg.OrchestratorURL, 30)
		ch <- orchJobsMsg{ch: ch, jobs: jobs, err: err}
	}()
	return listen(ch)
}

// submit posts a new discover-and-audit job. Active/intrusive checks aren't
// exposed here — same call the audit tab makes: that flag needs an explicit
// authorization the TUI can't collect, so it stays off from this screen.
func (t *orchestratorTab) submit() tea.Cmd {
	cidr := strings.TrimSpace(t.cidrIn.Value())
	if cidr == "" {
		return nil
	}
	t.status = "Отправляю задачу..."
	cfg := t.cfg
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id, err := orchclient.SubmitDiscoverAndAudit(ctx, cfg.OrchestratorURL, orchclient.DiscoverAuditRequest{
			CIDR: cidr, WithDNS: true,
		})
		return orchSubmitMsg{jobID: id, err: err}
	}
}

// startPolling watches one just-submitted job for up to a minute, or until it
// leaves "pending". A single ListJobs call up front seeds the jobs table with
// the new row (for its CIDR/created_at); after that, each tick uses GetJob —
// one indexed-row lookup — instead of re-listing and re-decoding every job's
// full result blob just to read one job's status.
func (t *orchestratorTab) startPolling(jobID string) tea.Cmd {
	cfg := t.cfg
	ch := make(chan tea.Msg, orchPollBufferSize)
	t.ch = ch
	t.polling = true
	go func() {
		listCtx, listCancel := context.WithTimeout(context.Background(), 5*time.Second)
		jobs, err := orchclient.ListJobs(listCtx, cfg.OrchestratorURL, 30)
		listCancel()
		ch <- orchJobsMsg{ch: ch, jobs: jobs, err: err}

		poll := func() (stillPending bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			job, err := orchclient.GetJob(ctx, cfg.OrchestratorURL, jobID)
			ch <- orchJobPollMsg{ch: ch, jobID: jobID, job: job, err: err}
			if err != nil {
				return true
			}
			return job.Result.Status == "pending"
		}
		for i := 0; i < 40 && poll(); i++ {
			time.Sleep(1500 * time.Millisecond)
		}
		ch <- orchPollDoneMsg{ch: ch}
	}()
	return listen(ch)
}

// upsertJobSummary applies one polled job's latest status/host count to
// t.jobs in place, or inserts it at the front if the seeding ListJobs call
// hadn't picked it up yet.
func (t *orchestratorTab) upsertJobSummary(jobID string, job orchclient.Job) {
	sum := orchclient.JobSummary{
		JobID:     jobID,
		Kind:      job.Kind,
		Status:    job.Result.Status,
		CIDR:      job.Result.CIDR,
		HostCount: len(job.Result.Hosts),
	}
	for i := range t.jobs {
		if t.jobs[i].JobID == jobID {
			sum.CreatedAt = t.jobs[i].CreatedAt
			t.jobs[i] = sum
			return
		}
	}
	sum.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
	t.jobs = append([]orchclient.JobSummary{sum}, t.jobs...)
}

// fetchDetail loads one job's full per-host results.
func (t *orchestratorTab) fetchDetail(jobID string) tea.Cmd {
	cfg := t.cfg
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		job, err := orchclient.GetJob(ctx, cfg.OrchestratorURL, jobID)
		return orchDetailMsg{jobID: jobID, job: job, err: err}
	}
}

func (t *orchestratorTab) Update(msg tea.Msg) (tab, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return t.handleKey(msg)

	case orchHealthMsg:
		if msg.ch != t.ch {
			return t, nil
		}
		t.healthChecked = true
		t.orchOK, t.auditOK, t.scanOK = msg.orchOK, msg.auditOK, msg.scanOK
		t.orchErrS, t.auditErrS, t.scanErrS = msg.orchErr, msg.auditErr, msg.scanErr
		return t, listen(t.ch) // refresh() always follows up with one orchJobsMsg

	case orchJobsMsg:
		if msg.ch != t.ch {
			return t, nil
		}
		t.jobs, t.jobsErr = msg.jobs, msg.err
		t.refreshJobsRows()
		if t.polling {
			return t, listen(t.ch)
		}
		return t, nil

	case orchJobPollMsg:
		if msg.ch != t.ch {
			return t, nil
		}
		if msg.err == nil {
			t.upsertJobSummary(msg.jobID, msg.job)
			t.refreshJobsRows()
		}
		if t.polling {
			return t, listen(t.ch)
		}
		return t, nil

	case orchPollDoneMsg:
		if msg.ch != t.ch {
			return t, nil
		}
		t.polling = false
		return t, nil

	case orchSubmitMsg:
		if msg.err != nil {
			t.status = t.sty.bad.Render("Ошибка: " + msg.err.Error())
			return t, nil
		}
		t.status = t.sty.good.Render("Задача отправлена: " + shortID(msg.jobID))
		t.cidrIn.SetValue("")
		return t, t.startPolling(msg.jobID)

	case orchDetailMsg:
		if msg.jobID != t.detailID {
			return t, nil // superseded by a newer detail fetch
		}
		if msg.err != nil {
			t.detailErr = msg.err
			return t, nil
		}
		t.detail = &msg.job
		t.detailErr = nil
		t.refreshHostsRows()
		return t, nil
	}
	return t, nil
}

func (t *orchestratorTab) handleKey(msg tea.KeyMsg) (tab, tea.Cmd) {
	switch t.view {
	case orchViewForm:
		switch msg.String() {
		case "enter":
			return t, t.submit()
		case "esc":
			t.cidrIn.Blur()
			t.view = orchViewList
			return t, nil
		}
		var cmd tea.Cmd
		t.cidrIn, cmd = t.cidrIn.Update(msg)
		return t, cmd

	case orchViewList:
		switch msg.String() {
		case "esc", "n":
			t.view = orchViewForm
			return t, t.cidrIn.Focus()
		case "r":
			return t, t.refresh()
		case "enter":
			if j := t.selectedJob(); j != nil {
				t.view = orchViewDetail
				t.detail, t.detailErr = nil, nil
				t.detailID = j.JobID
				t.hostsTbl.SetRows(nil)
				return t, t.fetchDetail(j.JobID)
			}
			return t, nil
		}
		var cmd tea.Cmd
		t.jobsTbl, cmd = t.jobsTbl.Update(msg)
		return t, cmd

	case orchViewDetail:
		switch msg.String() {
		case "esc":
			t.view = orchViewList
			return t, nil
		case "r":
			if t.detailID != "" {
				return t, t.fetchDetail(t.detailID)
			}
			return t, nil
		}
		var cmd tea.Cmd
		t.hostsTbl, cmd = t.hostsTbl.Update(msg)
		return t, cmd
	}
	return t, nil
}

// selectedJob maps the jobs table's cursor to the underlying job it lists.
func (t *orchestratorTab) selectedJob() *orchclient.JobSummary {
	i := t.jobsTbl.Cursor()
	if i < 0 || i >= len(t.jobs) {
		return nil
	}
	return &t.jobs[i]
}

// selectedHost maps the hosts table's cursor to the underlying host result.
func (t *orchestratorTab) selectedHost() *orchclient.HostResult {
	if t.detail == nil {
		return nil
	}
	i := t.hostsTbl.Cursor()
	if i < 0 || i >= len(t.detail.Result.Hosts) {
		return nil
	}
	return &t.detail.Result.Hosts[i]
}

func orchJobsColumns(w int) []table.Column {
	const idW, statusW, hostsW, timeW = 10, 10, 8, 17
	cidrW := max(w-idW-statusW-hostsW-timeW-10, 16)
	return []table.Column{
		{Title: "ID", Width: idW},
		{Title: "CIDR", Width: cidrW},
		{Title: "Статус", Width: statusW},
		{Title: "Хостов", Width: hostsW},
		{Title: "Время", Width: timeW},
	}
}

func orchHostsColumns(w int) []table.Column {
	const ipW, gradeW, findW = 16, 8, 10
	errW := max(w-ipW-gradeW-findW-8, 20)
	return []table.Column{
		{Title: "IP", Width: ipW},
		{Title: "Оценка", Width: gradeW},
		{Title: "Находок", Width: findW},
		{Title: "Ошибка", Width: errW},
	}
}

func (t *orchestratorTab) refreshJobsRows() {
	rows := make([]table.Row, 0, len(t.jobs))
	for _, j := range t.jobs {
		rows = append(rows, table.Row{
			shortID(j.JobID),
			trunc(j.CIDR, 24),
			j.Status,
			fmt.Sprint(j.HostCount),
			fmtJobTime(j.CreatedAt),
		})
	}
	t.jobsTbl.SetRows(rows)
}

func (t *orchestratorTab) refreshHostsRows() {
	if t.detail == nil {
		t.hostsTbl.SetRows(nil)
		return
	}
	hosts := t.detail.Result.Hosts
	rows := make([]table.Row, 0, len(hosts))
	for _, h := range hosts {
		grade, findings, errS := "-", "-", "-"
		if h.Audit != nil {
			grade = h.Audit.Grade
			findings = fmt.Sprint(len(h.Audit.Findings))
		}
		if h.Error != "" {
			errS = trunc(h.Error, 40)
		}
		rows = append(rows, table.Row{h.IP, grade, findings, errS})
	}
	t.hostsTbl.SetRows(rows)
}

// shortID truncates a UUID job id to its first segment — enough to tell rows
// apart on screen without eating column width.
func shortID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return id[:i]
	}
	return trunc(id, 8)
}

// fmtJobTime reformats SQLite's "YYYY-MM-DD HH:MM:SS" CURRENT_TIMESTAMP text
// into the same short form historyTab uses; falls back to the raw value.
func fmtJobTime(raw string) string {
	tm, err := time.Parse("2006-01-02 15:04:05", raw)
	if err != nil {
		return trunc(raw, 16)
	}
	return tm.Format("01-02 15:04")
}

func (t *orchestratorTab) View() string {
	var b strings.Builder
	b.WriteString(t.healthLine())
	b.WriteString("\n\n")

	switch t.view {
	case orchViewDetail:
		t.viewDetail(&b)
	case orchViewList:
		t.viewList(&b)
	default:
		t.viewForm(&b)
	}

	return lipgloss.Place(t.w, t.h, lipgloss.Left, lipgloss.Top,
		t.sty.frame("Оркестратор (discover + audit + Wazuh)", t.w, t.h, b.String()))
}

// healthLine renders a colored dot per service, refreshed by refresh().
func (t *orchestratorTab) healthLine() string {
	if !t.healthChecked {
		return t.sty.muted.Render("Проверяю сервисы...")
	}
	dot := func(ok bool, label, errS string) string {
		if ok {
			return t.sty.good.Render("● " + label)
		}
		suffix := ""
		if errS != "" {
			suffix = t.sty.muted.Render(" (" + healthReason(errS) + ")")
		}
		return t.sty.bad.Render("● "+label) + suffix
	}
	line := strings.Join([]string{
		dot(t.orchOK, "orchestrator", t.orchErrS),
		dot(t.auditOK, "audit-svc", t.auditErrS),
		dot(t.scanOK, "scan-svc", t.scanErrS),
	}, "   ")
	if !t.orchOK || !t.auditOK || !t.scanOK {
		line += "\n" + t.sty.muted.Render("Запуск сервисов: docker compose -f deploy/docker-compose.yml up -d --build")
	}
	return line
}

// healthReason turns a raw HTTP client error into a short human reason: the
// full "Get \"http://...\": dial tcp ..." text never fits the health strip.
func healthReason(errS string) string {
	low := strings.ToLower(errS)
	switch {
	case strings.Contains(low, "refused"), strings.Contains(low, "actively refused"):
		return "не запущен"
	case strings.Contains(low, "deadline exceeded"), strings.Contains(low, "timeout"):
		return "нет ответа"
	case strings.Contains(low, "no such host"):
		return "неизвестный хост"
	}
	if i := strings.LastIndex(errS, ": "); i >= 0 {
		errS = errS[i+2:]
	}
	return trunc(errS, 32)
}

func (t *orchestratorTab) viewForm(b *strings.Builder) {
	b.WriteString(t.cidrIn.View())
	b.WriteString("\n")
	if hint := cidrHint(t.sty, t.cidrIn.Value()); hint != "" {
		b.WriteString(hint)
	} else {
		b.WriteString(t.sty.muted.Render("Discover + audit по подсети через оркестратор; находки уедут в Wazuh, если он подключён."))
	}
	if t.status != "" {
		b.WriteString("\n\n")
		b.WriteString(t.status)
	}
	if t.polling {
		fmt.Fprintf(b, "\n%s", t.sty.accent.Render("● отслеживаю выполнение..."))
	}
	fmt.Fprintf(b, "\n\n%s\n", t.sty.muted.Render(fmt.Sprintf("Задач в истории: %d. [Esc] — посмотреть список.", len(t.jobs))))
}

func (t *orchestratorTab) viewList(b *strings.Builder) {
	if t.jobsErr != nil {
		fmt.Fprintf(b, "%s\n\n", t.sty.bad.Render("Ошибка загрузки списка: "+t.jobsErr.Error()))
	}
	if len(t.jobs) == 0 && t.jobsErr == nil {
		b.WriteString(t.sty.muted.Render("Задач ещё не было. [Esc] — отправить новую."))
		return
	}
	b.WriteString(t.jobsTbl.View())
}

func (t *orchestratorTab) viewDetail(b *strings.Builder) {
	if t.detailErr != nil {
		fmt.Fprintf(b, "%s\n\n", t.sty.bad.Render("Ошибка загрузки задачи: "+t.detailErr.Error()))
		return
	}
	if t.detail == nil {
		b.WriteString(t.sty.muted.Render("Загружаю..."))
		return
	}
	res := t.detail.Result
	fmt.Fprintf(b, "%s  %s\n\n",
		t.sty.big.Render(res.CIDR),
		t.sty.muted.Render(fmt.Sprintf("статус: %s, хостов: %d", res.Status, len(res.Hosts))))
	if res.Error != "" {
		fmt.Fprintf(b, "%s\n\n", t.sty.bad.Render("Ошибка: "+res.Error))
	}
	b.WriteString(t.hostsTbl.View())

	if h := t.selectedHost(); h != nil && h.Audit != nil && len(h.Audit.Findings) > 0 {
		b.WriteString("\n\n")
		fmt.Fprintf(b, "%s\n", t.sty.big.Render("Находки: "+h.IP))
		for _, f := range h.Audit.Findings {
			fmt.Fprintf(b, "  %s  %s\n", orchSevBadge(t.sty, f.Severity), t.sty.muted.Render(f.Title))
		}
	}
}

// orchSevBadge colors a finding's severity label — the Russian string
// audit.Severity.MarshalJSON emits (see internal/audit/audit.go), the same
// values the audit tab's sevBadge colors from the enum directly.
func orchSevBadge(s styles, sev string) string {
	label := fmt.Sprintf("%-9s", sev)
	switch strings.ToLower(sev) {
	case "критично", "высокая":
		return s.bad.Render(label)
	case "средняя":
		return s.warn.Render(label)
	case "низкая":
		return s.accent.Render(label)
	default:
		return s.muted.Render(label)
	}
}
