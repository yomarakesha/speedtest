package audit

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// pathProbe describes one sensitive URL to look for. needle, when set, must
// appear in the response body for the finding to fire — this filters out servers
// that answer 200 to everything (soft-404s / catch-all SPAs). rawFile marks a
// probe whose target is a plain (non-HTML) file: an HTML response then means a
// catch-all SPA served its shell, not the file, and the finding is suppressed.
type pathProbe struct {
	path    string
	sev     Severity
	title   string
	needle  string
	rawFile bool
}

// sensitivePaths are common exposures worth checking on a web server. Each is a
// real, high-signal leak when reachable — source-control metadata, secrets
// files, status/monitoring endpoints, backups.
var sensitivePaths = []pathProbe{
	{path: "/.git/HEAD", sev: High, title: "Открыт каталог .git (утечка исходного кода)", needle: "ref:", rawFile: true},
	{path: "/.env", sev: Critical, title: "Доступен файл .env (секреты приложения)", needle: "=", rawFile: true},
	{path: "/.svn/entries", sev: Medium, title: "Открыты метаданные Subversion", rawFile: true},
	{path: "/.aws/credentials", sev: Critical, title: "Доступны учётные данные AWS", rawFile: true},
	{path: "/server-status", sev: Medium, title: "Открыта страница mod_status Apache", needle: "Apache Server Status"},
	{path: "/actuator/health", sev: Medium, title: "Открыт Spring Boot Actuator", needle: "status"},
	{path: "/actuator/env", sev: High, title: "Actuator /env раскрывает конфигурацию и секреты"},
	{path: "/actuator/heapdump", sev: High, title: "Actuator отдаёт heapdump (утечка памяти процесса)", needle: "JAVA PROFILE", rawFile: true},
	{path: "/phpinfo.php", sev: Medium, title: "Доступна страница phpinfo()", needle: "phpinfo()"},
	{path: "/.DS_Store", sev: Low, title: "Открыт файл .DS_Store (утечка структуры каталогов)", rawFile: true},
	{path: "/backup.zip", sev: Medium, title: "Доступен архив резервной копии", rawFile: true},
	{path: "/wp-config.php.bak", sev: High, title: "Доступна резервная копия wp-config", rawFile: true},
	{path: "/.well-known/security.txt", sev: Info, title: "Опубликован security.txt"},
}

// AuditWebPaths probes a web server for well-known sensitive paths. It first
// fetches a random path to learn the server's "not found" behaviour, then flags
// only responses that both return 200 and differ from that baseline (and match
// the probe's needle, when given). target may be a bare host or a URL.
func AuditWebPaths(target string, timeout time.Duration) []Finding {
	base := webBaseURL(target)
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // audit tool assesses trust separately
		},
	}

	// Baseline: a path that should not exist. If the server answers it 200 with a
	// body, it is a catch-all and path probing would be all false positives.
	randPath := fmt.Sprintf("/nonexistent-%d-%d", time.Now().UnixNano(), rand.Intn(1e6))
	baseStatus, baseLen, ok := fetchPath(client, base+randPath)
	if !ok {
		return nil // server unreachable over HTTP
	}
	catchAll := baseStatus == http.StatusOK && baseLen > 0

	var (
		mu  sync.Mutex
		out []Finding
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 8)
	for _, p := range sensitivePaths {
		wg.Add(1)
		go func(p pathProbe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if f := probePath(client, base, p, catchAll, baseLen); f != nil {
				mu.Lock()
				out = append(out, *f)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return out
}

// probePath fetches one sensitive path and returns a Finding when it looks
// genuinely exposed.
func probePath(client *http.Client, base string, p pathProbe, catchAll bool, baseLen int) *Finding {
	status, body, ok := fetchBody(client, base+p.path)
	if !ok || status != http.StatusOK {
		return nil
	}
	// A raw file (.env, .git/HEAD, credentials, backups) is never HTML: an HTML
	// body means a catch-all SPA served its shell (e.g. MinIO/React consoles
	// return index.html for any path), so this is a false positive.
	if p.rawFile && looksHTML(body) {
		return nil
	}
	// A needle is the strongest signal; when present it alone decides.
	if p.needle != "" {
		if !strings.Contains(body, p.needle) {
			return nil
		}
	} else {
		// No needle: reject if the server is a catch-all or the body is
		// indistinguishable from the not-found baseline.
		if catchAll || len(body) == baseLen {
			return nil
		}
	}
	return &Finding{
		Check:    "web.sensitive_path",
		Severity: p.sev,
		Title:    p.title,
		Detail:   "доступно по " + p.path,
		Evidence: p.path,
	}
}

// looksHTML reports whether a response body is an HTML document, so raw-file
// probes can reject a catch-all SPA shell served in place of the real file.
func looksHTML(body string) bool {
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.Contains(head, "<!doctype html") || strings.Contains(head, "<html")
}

// webBaseURL returns the scheme+host base for path probing. A bare host defaults
// to http:// (internal panels and leaks are commonly plaintext); an explicit
// scheme is preserved. Any path in target is dropped.
func webBaseURL(target string) string {
	scheme := "http://"
	rest := target
	if i := strings.Index(target, "://"); i >= 0 {
		scheme = target[:i+3]
		rest = target[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return scheme + rest
}

// fetchPath does a GET and returns the status and body length, discarding the
// body. ok is false on a transport error.
func fetchPath(client *http.Client, url string) (status, bodyLen int, ok bool) {
	status, body, ok := fetchBody(client, url)
	return status, len(body), ok
}

// fetchBody does a GET and returns the status and a bounded body.
func fetchBody(client *http.Client, url string) (status int, body string, ok bool) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, string(b), true
}
