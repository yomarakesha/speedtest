package portscan

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Subdomain is one name discovered under the scanned domain.
type Subdomain struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs,omitempty"`
	Sources []string `json:"sources"`
}

// Source labels for a discovered name, in the output language of the CLI.
const (
	srcBrute = "перебор"
	srcCert  = "сертификат"
	srcMX    = "MX"
	srcNS    = "NS"
	srcCNAME = "CNAME"
	srcCT    = "CT-лог"
)

// SubdomainOptions configures an enumeration run.
type SubdomainOptions struct {
	Domain   string        // name that was scanned, e.g. "www.example.com"
	Addr     string        // address it resolved to, used for certificate probing
	Ports    []int         // open ports; the TLS-speaking ones are probed for names
	Timeout  time.Duration // per-lookup / per-handshake budget
	Workers  int           // concurrent DNS lookups
	Wordlist []string      // nil => defaultSubdomainWords
	NoCT     bool          // skip the Certificate Transparency (crt.sh) lookup
	Resolve  bool          // resolve names found by passive sources (CT/cert) too
}

// SubdomainResult is the outcome of enumerating one domain.
type SubdomainResult struct {
	Base     string      `json:"base"`               // registrable domain the search ran under
	Wildcard []string    `json:"wildcard,omitempty"` // addresses a catch-all *.base answers with
	Found    []Subdomain `json:"found,omitempty"`
}

// EnumSubdomains looks for other names under the scanned domain, combining three
// sources that need no third-party service: a dictionary of common labels
// resolved against DNS, the domain's own MX/NS records, and the names listed in
// the TLS certificates served on its open ports. Wildcard DNS is detected first
// so a catch-all zone doesn't report the whole dictionary as real.
func EnumSubdomains(ctx context.Context, opt SubdomainOptions) SubdomainResult {
	base := baseDomain(opt.Domain)
	if base == "" {
		return SubdomainResult{}
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	workers := opt.Workers
	if workers < 1 {
		workers = 50
	}
	words := opt.Wordlist
	if len(words) == 0 {
		words = defaultSubdomainWords
	}

	res := SubdomainResult{Base: base}
	res.Wildcard = wildcardAddrs(ctx, base, timeout)

	found := map[string]*Subdomain{}
	var mu sync.Mutex
	add := func(name, source string, addrs []string) {
		name = normalizeName(name)
		if name == "" || name == base || !strings.HasSuffix(name, "."+base) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		s, ok := found[name]
		if !ok {
			s = &Subdomain{Name: name}
			found[name] = s
		}
		if !slices.Contains(s.Sources, source) {
			s.Sources = append(s.Sources, source)
		}
		for _, a := range addrs {
			if !slices.Contains(s.Addrs, a) {
				s.Addrs = append(s.Addrs, a)
			}
		}
	}

	// Dictionary sweep. A hit whose addresses are exactly the wildcard answer is
	// the catch-all replying, not a real host, so it is dropped.
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, w := range words {
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			name := word + "." + base
			addrs := lookupAddrs(ctx, name, timeout)
			if len(addrs) == 0 || sameAddrs(addrs, res.Wildcard) {
				return
			}
			add(name, srcBrute, addrs)
		}(w)
	}

	// Records the zone publishes about itself.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for name, source := range zoneRecords(ctx, base, timeout) {
			add(name, source, lookupAddrs(ctx, name, timeout))
		}
	}()

	// passiveResolve decides whether a name from a passive source (cert/CT, which
	// prove a name existed but not that it resolves today) is looked up. Wildcards
	// never resolve, so they are always left address-less.
	passiveResolve := func(name string) []string {
		if !opt.Resolve || strings.HasPrefix(name, "*.") {
			return nil
		}
		return lookupAddrs(ctx, name, timeout)
	}

	// Names the host's own certificates claim.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, name := range certNames(ctx, opt.Addr, opt.Domain, opt.Ports, timeout) {
			add(name, srcCert, passiveResolve(name))
		}
	}()

	// Names logged in public Certificate Transparency (crt.sh). This is the
	// deepest source — every cert a CA ever issued for the zone is public — so it
	// finds hosts a dictionary never would. Best-effort: a network or rate-limit
	// error just contributes nothing.
	if !opt.NoCT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, name := range ctLogNames(ctx, base, ctTimeout(timeout)) {
				add(name, srcCT, passiveResolve(name))
			}
		}()
	}
	wg.Wait()

	res.Found = make([]Subdomain, 0, len(found))
	for _, s := range found {
		sort.Strings(s.Addrs)
		sort.Strings(s.Sources)
		res.Found = append(res.Found, *s)
	}
	sort.Slice(res.Found, func(i, j int) bool { return res.Found[i].Name < res.Found[j].Name })
	return res
}

// multiLabelSuffixes are public suffixes made of two labels, where the
// registrable domain is three labels deep (e.g. "shop.co.uk", not "co.uk").
// A short list covers the cases a LAN/web operator actually scans; anything
// missing degrades to treating the last two labels as the base, which only
// widens or narrows the search rather than breaking it.
var multiLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.nz": true, "co.za": true,
	"com.br": true, "com.ar": true, "com.mx": true, "com.tr": true, "com.cn": true,
	"co.jp": true, "co.kr": true, "co.in": true, "com.ua": true, "org.ua": true,
	"com.pl": true, "com.sg": true, "com.hk": true, "com.tw": true, "co.il": true,
}

// baseDomain reduces a host to the registrable domain to enumerate under, so
// scanning "api.stage.example.com" still searches all of "example.com".
func baseDomain(host string) string {
	h := normalizeName(host)
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	labels := strings.Split(h, ".")
	if len(labels) < 3 {
		return h
	}
	if multiLabelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// normalizeName lowercases a DNS name and strips the trailing root dot.
func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// wildcardAddrs returns the addresses a catch-all record answers with, or nil
// when the zone has no wildcard. A label no one would register is queried; if it
// resolves, every dictionary hit with the same answer is that wildcard.
func wildcardAddrs(ctx context.Context, base string, timeout time.Duration) []string {
	return lookupAddrs(ctx, "zzq7x9k1v3-wildcard-probe."+base, timeout)
}

// lookupAddrs resolves a name to its sorted addresses, or nil.
func lookupAddrs(ctx context.Context, name string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// zoneRecords returns the names the domain publishes in its own MX, NS and
// CNAME records, mapped to the source that revealed each one.
func zoneRecords(ctx context.Context, base string, timeout time.Duration) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := map[string]string{}
	if mxs, err := net.DefaultResolver.LookupMX(ctx, base); err == nil {
		for _, mx := range mxs {
			out[normalizeName(mx.Host)] = srcMX
		}
	}
	if nss, err := net.DefaultResolver.LookupNS(ctx, base); err == nil {
		for _, ns := range nss {
			out[normalizeName(ns.Host)] = srcNS
		}
	}
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, base); err == nil {
		out[normalizeName(cname)] = srcCNAME
	}
	return out
}

// ctTimeout gives the crt.sh query a larger budget than a single DNS lookup: the
// public CT index is frequently slow and sometimes returns 502 under load, so a
// too-short deadline would never see a good answer.
func ctTimeout(base time.Duration) time.Duration {
	if base < 12*time.Second {
		return 12 * time.Second
	}
	return base
}

// ctEntry is one row of the crt.sh JSON response. name_value holds one or more
// names (newline-separated), each a subject or SAN entry from a logged cert.
type ctEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// ctLogNames queries crt.sh — a public mirror of the Certificate Transparency
// logs every CA is required to publish to — for names ever certified under base.
// It returns the distinct names; the caller filters them to the zone. This needs
// no API key and reveals hosts (internal, staging, decommissioned) that never
// appear in a dictionary. A failure returns nil.
func ctLogNames(ctx context.Context, base string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := "https://crt.sh/?q=%25." + base + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "speedtest-scan/1.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	return parseCTEntries(io.LimitReader(resp.Body, 16<<20))
}

// parseCTEntries decodes a crt.sh JSON response into the distinct, normalized
// names it lists. Split out from the HTTP fetch so the parsing is testable
// without hitting the network.
func parseCTEntries(r io.Reader) []string {
	var entries []ctEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	consider := func(name string) {
		name = normalizeName(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, e := range entries {
		consider(e.CommonName)
		for n := range strings.SplitSeq(e.NameValue, "\n") {
			consider(n)
		}
	}
	return out
}

// certNames returns the DNS names listed in the certificates served on the
// host's open TLS ports. The certificate is read, never trusted: an expired or
// self-signed one still names the hosts it was issued for.
func certNames(ctx context.Context, addr, serverName string, ports []int, timeout time.Duration) []string {
	if addr == "" {
		return nil
	}
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for _, p := range ports {
		if !tlsPorts[p] {
			continue
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			names := certNamesOnPort(ctx, addr, serverName, port, timeout)
			mu.Lock()
			out = append(out, names...)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return out
}

// certNamesOnPort handshakes with one port and returns the subject CN plus every
// SAN entry of the presented chain.
func certNamesOnPort(ctx context.Context, addr, serverName string, port int, timeout time.Duration) []string {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(addr, fmt.Sprint(port)),
		&tls.Config{InsecureSkipVerify: true, ServerName: serverName}) //nolint:gosec // reading the cert, not trusting it
	if err != nil {
		return nil
	}
	defer conn.Close()
	if ctx.Err() != nil {
		return nil
	}
	var out []string
	for _, c := range conn.ConnectionState().PeerCertificates {
		if c.Subject.CommonName != "" {
			out = append(out, c.Subject.CommonName)
		}
		out = append(out, c.DNSNames...)
	}
	return out
}

// sameAddrs reports whether two sorted address sets are identical and non-empty.
func sameAddrs(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// defaultSubdomainWords is the dictionary swept against the zone: the labels an
// organisation is most likely to publish, covering mail, infrastructure,
// environments, and common self-hosted services.
var defaultSubdomainWords = []string{
	"www", "www2", "ww1", "m", "mobile", "web", "web1", "web2", "portal", "home",
	"mail", "mail1", "mail2", "webmail", "smtp", "smtp2", "imap", "pop", "pop3",
	"mx", "mx1", "mx2", "relay", "email", "exchange", "owa", "autodiscover", "autoconfig",
	"ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	"vpn", "vpn2", "remote", "gw", "gateway", "router", "firewall", "proxy", "edge",
	"ftp", "sftp", "files", "file", "share", "storage", "backup", "backups", "nas",
	"api", "api2", "app", "apps", "auth", "sso", "login", "account", "accounts", "id", "oauth",
	"admin", "panel", "cpanel", "whm", "plesk", "dashboard", "manage", "manager", "console",
	"dev", "test", "qa", "uat", "stage", "staging", "prod", "preview", "sandbox", "demo", "beta", "alpha", "lab",
	"git", "gitlab", "github", "svn", "repo", "registry", "nexus", "artifactory", "docker", "ci", "jenkins", "build",
	"k8s", "kube", "rancher", "consul", "vault", "nomad",
	"db", "sql", "mysql", "postgres", "mssql", "oracle", "mongo", "redis", "elastic", "elasticsearch", "kibana",
	"monitor", "monitoring", "grafana", "prometheus", "zabbix", "nagios", "status", "metrics", "logs", "log", "syslog",
	"cdn", "static", "assets", "img", "images", "media", "video", "stream", "download", "downloads", "s3", "origin",
	"blog", "news", "forum", "wiki", "docs", "doc", "kb", "help", "support", "helpdesk", "ticket", "tickets",
	"shop", "store", "cart", "checkout", "pay", "payment", "payments", "billing", "invoice", "order", "orders",
	"crm", "erp", "hr", "intranet", "extranet", "internal", "private", "partner", "partners", "corp",
	"jira", "confluence", "sharepoint", "teams", "chat", "im", "voip", "sip", "pbx", "asterisk", "conf", "meet",
	"ldap", "ad", "dc", "radius", "kerberos", "ca", "pki", "cert",
	"cam", "camera", "cctv", "nvr", "dvr", "iot", "sensor", "print", "printer", "scanner",
	"old", "new", "legacy", "temp", "tmp", "test2", "secure", "ssl", "public", "cloud", "host", "server", "srv",
	"ws", "wss", "socket", "push", "events", "queue", "mq", "rabbit", "kafka", "cache", "search", "solr",
	"track", "tracking", "analytics", "stats", "ads", "campaign", "mailer", "newsletter", "list",
	"careers", "jobs", "press", "investors", "legal", "about", "contact", "learn", "training", "academy",
}
