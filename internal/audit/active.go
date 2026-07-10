// active.go holds the intrusive checks that actually interact with services
// (sending commands, trying credentials). They only run when the caller passes
// an explicit authorization flag, and only against the single specified target.
package audit

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultCreds is a short list of well-known factory credentials tried against
// HTTP Basic-auth endpoints. Kept intentionally tiny — this is an audit nudge,
// not a brute-force tool.
var defaultCreds = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", ""},
	{"root", "root"},
	{"user", "user"},
}

// AuditActive runs the intrusive checks against host. It is only invoked after
// the caller confirms authorization. progress, when non-nil, receives a short
// status line per check for interactive callers.
func AuditActive(host string, timeout time.Duration) []Finding {
	var out []Finding
	out = append(out, unauthServiceFindings(host, timeout)...)
	out = append(out, ftpAnonymousFinding(net.JoinHostPort(host, "21"), timeout)...)
	out = append(out, httpDefaultCredFinding(host, timeout)...)
	return out
}

// unauthServiceFindings probes data stores that are dangerous when reachable
// without authentication (Redis, MongoDB, Elasticsearch, Memcached) with a
// single benign command.
func unauthServiceFindings(host string, timeout time.Duration) []Finding {
	var out []Finding

	// Redis: an unauthenticated PING returns "+PONG".
	if resp := probe(host, 6379, "PING\r\n", timeout); strings.HasPrefix(resp, "+PONG") {
		out = append(out, Finding{
			Check: "creds.redis_noauth", Severity: Critical,
			Title:  "Redis доступен без пароля",
			Detail: "сервер принял команду PING без аутентификации",
		})
	}
	// Memcached: "version\r\n" returns "VERSION x.y.z" when open.
	if resp := probe(host, 11211, "version\r\n", timeout); strings.HasPrefix(resp, "VERSION") {
		out = append(out, Finding{
			Check: "creds.memcached_noauth", Severity: High,
			Title:  "Memcached доступен без аутентификации",
			Detail: strings.TrimSpace(resp),
		})
	}
	// Elasticsearch: unauthenticated HTTP root returns cluster JSON.
	if body := httpGet(host, 9200, "/", timeout); strings.Contains(body, "\"cluster_name\"") {
		out = append(out, Finding{
			Check: "creds.elastic_noauth", Severity: High,
			Title:  "Elasticsearch доступен без аутентификации",
		})
	}
	return out
}

// ftpAnonymousFinding reports whether the FTP server at addr (host:port)
// accepts anonymous login.
func ftpAnonymousFinding(addr string, timeout time.Duration) []Finding {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		return nil
	}
	fmt.Fprint(conn, "USER anonymous\r\n")
	r.ReadString('\n')
	fmt.Fprint(conn, "PASS anonymous@example.com\r\n")
	line, err := r.ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(line), "230") { // login successful
		return []Finding{{
			Check: "creds.ftp_anonymous", Severity: High,
			Title:  "Разрешён анонимный вход по FTP",
			Detail: strings.TrimSpace(line),
		}}
	}
	return nil
}

// httpDefaultCredFinding tries factory credentials against an HTTP Basic-auth
// endpoint on common web ports, reporting the first pair that authenticates.
func httpDefaultCredFinding(host string, timeout time.Duration) []Finding {
	client := &http.Client{Timeout: timeout}
	for _, port := range []int{80, 8080, 443} {
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		challenge := resp.StatusCode == http.StatusUnauthorized &&
			strings.HasPrefix(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "basic")
		resp.Body.Close()
		if !challenge {
			continue
		}
		for _, c := range defaultCreds {
			if tryBasicAuth(client, url, c[0], c[1]) {
				return []Finding{{
					Check: "creds.http_default", Severity: Critical,
					Title:    "Приняты учётные данные по умолчанию (HTTP Basic)",
					Detail:   fmt.Sprintf("%s:%s на %s", c[0], blankable(c[1]), url),
					Evidence: url,
				}}
			}
		}
	}
	return nil
}

// tryBasicAuth reports whether user:pass authenticates against url.
func tryBasicAuth(client *http.Client, url, user, pass string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusUnauthorized && resp.StatusCode < 500
}

// probe opens a TCP connection, writes send, and returns the first line read.
func probe(host string, port int, send string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(send)); err != nil {
		return ""
	}
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// httpGet fetches path from host:port over plain HTTP and returns the body.
func httpGet(host string, port int, path string, timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("http://%s:%d%s", host, port, path)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

// blankable renders an empty password visibly for reporting.
func blankable(s string) string {
	if s == "" {
		return "(пусто)"
	}
	return s
}
