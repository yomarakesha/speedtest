package audit

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readFTPReply must consume continuation lines and return only the final status
// line, so a multi-line banner/reply can't desync the anonymous-login check.
func TestReadFTPReply(t *testing.T) {
	in := "220-Welcome to vsFTPd\r\n220-Rules apply\r\n220 Ready\r\n331 Password required\r\n"
	r := bufio.NewReader(strings.NewReader(in))
	first, err := readFTPReply(r)
	if err != nil || first != "220 Ready" {
		t.Fatalf("first reply = %q, %v; want \"220 Ready\"", first, err)
	}
	second, err := readFTPReply(r)
	if err != nil || second != "331 Password required" {
		t.Fatalf("second reply = %q, %v; want \"331 Password required\"", second, err)
	}
}

func TestCVEForBanner(t *testing.T) {
	fs := cveForBanner("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13")
	if !hasCheck(fs, "cve.known_vulnerable") {
		t.Fatalf("expected CVE match for OpenSSH 6.6, got %+v", fs)
	}
	if len(cveForBanner("SSH-2.0-OpenSSH_9.6")) != 0 {
		t.Error("modern OpenSSH should not match any CVE rule")
	}
	if len(cveForBanner("")) != 0 {
		t.Error("empty banner should not match")
	}
}

func TestBlankable(t *testing.T) {
	if blankable("") != "(пусто)" {
		t.Error("empty password should render as (пусто)")
	}
	if blankable("x") != "x" {
		t.Error("non-empty password should pass through")
	}
}

// TestFTPAnonymousFinding stands up a minimal FTP server that accepts anonymous
// login and checks it is flagged.
func TestFTPAnonymousFinding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		c.Write([]byte("220 test ftp\r\n"))
		r.ReadString('\n') // USER
		c.Write([]byte("331 need password\r\n"))
		r.ReadString('\n') // PASS
		c.Write([]byte("230 login successful\r\n"))
	}()

	fs := ftpAnonymousFinding(ln.Addr().String(), time.Second)
	if !hasCheck(fs, "creds.ftp_anonymous") {
		t.Errorf("expected anonymous-FTP finding, got %+v", fs)
	}
}

// TestHTTPDefaultCredFinding serves a Basic-auth endpoint that accepts
// admin:admin and checks the default-cred probe reports it.
func TestHTTPDefaultCredFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "admin" && p == "admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := srv.Client()
	client.Timeout = 3 * time.Second
	url := srv.URL + "/"

	// Confirm the challenge is detected and a default pair authenticates.
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 challenge, got %d", resp.StatusCode)
	}
	if !tryBasicAuth(client, url, "admin", "admin") {
		t.Error("admin:admin should authenticate against the test server")
	}
	if tryBasicAuth(client, url, "admin", "wrong") {
		t.Error("wrong password should not authenticate")
	}
}
