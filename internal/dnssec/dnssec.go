// Package dnssec audits a domain's DNS security posture: SPF, DMARC and DKIM
// email-auth records, DNSSEC validation, CAA issuance records, and whether any
// of the domain's authoritative name servers allow a full zone transfer (AXFR).
//
// Record lookups use DNS-over-HTTPS (Cloudflare's JSON API) so the package needs
// no third-party DNS library. The AXFR probe speaks DNS-over-TCP directly, since
// DoH will not relay a zone transfer.
package dnssec

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"speedtest/internal/report"
	"speedtest/internal/util"
)

// dkimSelectors are common DKIM selectors probed in order.
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1"}

// Result is the full DNS-security audit of one domain.
type Result struct {
	Domain    string     `json:"domain"`
	SPF       string     `json:"spf,omitempty"`
	HasSPF    bool       `json:"has_spf"`
	DMARC     string     `json:"dmarc,omitempty"`
	DMARCPol  string     `json:"dmarc_policy,omitempty"`
	HasDMARC  bool       `json:"has_dmarc"`
	DKIM      string     `json:"dkim_selector,omitempty"`
	HasDKIM   bool       `json:"has_dkim"`
	DNSSEC    bool       `json:"dnssec"`
	CAA       []string   `json:"caa,omitempty"`
	AXFR      []AXFRHost `json:"axfr,omitempty"`
	AXFROpen  bool       `json:"axfr_open"`
	Nameservs []string   `json:"nameservers,omitempty"`
}

// AXFRHost is one name server's zone-transfer probe result.
type AXFRHost struct {
	NS      string `json:"ns"`
	Allowed bool   `json:"allowed"`
	Note    string `json:"note,omitempty"`
}

// dohAnswer is one record from the DoH JSON response.
type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	AD     bool        `json:"AD"` // Authenticated Data = DNSSEC-validated
	Answer []dohAnswer `json:"Answer"`
}

// doh queries Cloudflare's DoH JSON endpoint for name/qtype.
func doh(client *http.Client, name, qtype string) (dohResponse, error) {
	u := "https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(name) + "&type=" + qtype
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return dohResponse{}, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return dohResponse{}, err
	}
	defer resp.Body.Close()
	var out dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return dohResponse{}, err
	}
	return out, nil
}

// txtData extracts TXT strings from DoH answers, stripping the surrounding
// quotes DoH wraps them in.
func txtData(ans []dohAnswer) []string {
	var out []string
	for _, a := range ans {
		if a.Type == 16 { // TXT
			out = append(out, strings.Trim(a.Data, `"`))
		}
	}
	return out
}

// parseSPF returns the first SPF record among TXT strings, if any.
func parseSPF(txts []string) (string, bool) {
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			return t, true
		}
	}
	return "", false
}

// parseDMARC returns the DMARC record and its policy (p= tag value).
func parseDMARC(txts []string) (record, policy string, found bool) {
	for _, t := range txts {
		if !strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			continue
		}
		for _, part := range strings.Split(t, ";") {
			part = strings.TrimSpace(part)
			if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(strings.TrimSpace(k), "p") {
				policy = strings.TrimSpace(v)
			}
		}
		return t, policy, true
	}
	return "", "", false
}

// Audit performs the full DNS-security audit of domain.
func Audit(domain string, timeout time.Duration) (Result, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return Result{}, fmt.Errorf("пустой домен")
	}
	client := &http.Client{Timeout: timeout}
	res := Result{Domain: domain}

	if r, err := doh(client, domain, "TXT"); err == nil {
		res.SPF, res.HasSPF = parseSPF(txtData(r.Answer))
	}
	if r, err := doh(client, "_dmarc."+domain, "TXT"); err == nil {
		res.DMARC, res.DMARCPol, res.HasDMARC = parseDMARC(txtData(r.Answer))
	}
	for _, sel := range dkimSelectors {
		if r, err := doh(client, sel+"._domainkey."+domain, "TXT"); err == nil {
			for _, t := range txtData(r.Answer) {
				if strings.Contains(strings.ToLower(t), "v=dkim1") || strings.Contains(t, "p=") {
					res.DKIM, res.HasDKIM = sel, true
					break
				}
			}
		}
		if res.HasDKIM {
			break
		}
	}
	// DNSSEC: the AD flag on a validating resolver's answer.
	if r, err := doh(client, domain, "SOA"); err == nil {
		res.DNSSEC = r.AD
	}
	// CAA.
	if r, err := doh(client, domain, "CAA"); err == nil {
		for _, a := range r.Answer {
			if a.Type == 257 {
				res.CAA = append(res.CAA, a.Data)
			}
		}
	}
	// Name servers, then AXFR probe against each.
	if r, err := doh(client, domain, "NS"); err == nil {
		for _, a := range r.Answer {
			if a.Type == 2 {
				res.Nameservs = append(res.Nameservs, strings.TrimSuffix(a.Data, "."))
			}
		}
	}
	for _, ns := range res.Nameservs {
		h := probeAXFR(client, ns, domain, timeout)
		res.AXFR = append(res.AXFR, h)
		if h.Allowed {
			res.AXFROpen = true
		}
	}
	return res, nil
}

// buildQuery builds a DNS query message (without the 2-byte TCP length prefix)
// for name/qtype. recursion controls the RD flag.
func buildQuery(id uint16, name string, qtype uint16, recursion bool) []byte {
	var flags uint16
	if recursion {
		flags = 0x0100
	}
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[4:], 1) // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0) // root label
	msg = append(msg, 0, 0)
	binary.BigEndian.PutUint16(msg[len(msg)-2:], qtype)
	msg = append(msg, 0, 1) // QCLASS=IN
	return msg
}

// headerCounts extracts RCODE and ANCOUNT from a DNS response header.
func headerCounts(msg []byte) (rcode int, ancount int, ok bool) {
	if len(msg) < 12 {
		return 0, 0, false
	}
	rcode = int(msg[3] & 0x0f)
	ancount = int(binary.BigEndian.Uint16(msg[6:]))
	return rcode, ancount, true
}

// probeAXFR attempts a zone transfer of domain from ns. Allowed is true only
// when the server returns zone records instead of refusing.
func probeAXFR(client *http.Client, ns, domain string, timeout time.Duration) AXFRHost {
	h := AXFRHost{NS: ns}
	// Resolve the NS name to an IP via DoH.
	ip := ns
	if net.ParseIP(ns) == nil {
		if r, err := doh(client, ns, "A"); err == nil {
			for _, a := range r.Answer {
				if a.Type == 1 {
					ip = a.Data
					break
				}
			}
		}
	}
	addr := net.JoinHostPort(ip, "53")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		h.Note = "нет TCP-подключения к " + addr
		return h
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	q := buildQuery(0x1234, domain, 252, false) // 252 = AXFR
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		h.Note = "ошибка отправки запроса"
		return h
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		h.Note = "нет ответа"
		return h
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		h.Note = "обрыв ответа"
		return h
	}
	rcode, ancount, ok := headerCounts(resp)
	if !ok {
		h.Note = "короткий ответ"
		return h
	}
	if rcode == 0 && ancount > 0 {
		h.Allowed = true
		h.Note = fmt.Sprintf("передача зоны разрешена (%d записей в первом ответе)", ancount)
	} else {
		h.Note = fmt.Sprintf("отказано (rcode=%d)", rcode)
	}
	return h
}

// RunDNSSEC is the CLI entry point for `speedtest dnssec <domain>`.
func RunDNSSEC(args []string) error {
	fs := flag.NewFlagSet("dnssec", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 8*time.Second, "per-lookup timeout")
	asJSON := fs.Bool("json", false, "output result as JSON")
	wazuh := fs.Bool("wazuh", false, "emit findings to the Wazuh report log")
	pos, err := util.ParseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("использование: speedtest dnssec <domain>")
	}

	res, err := Audit(pos[0], *timeout)
	if err != nil {
		return err
	}

	if *wazuh {
		emitEvents(res)
	}

	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("DNS-безопасность %s\n", res.Domain)
	printFlag("SPF", res.HasSPF, res.SPF)
	if res.HasDMARC {
		printFlag("DMARC", true, res.DMARC+"  (policy="+res.DMARCPol+")")
	} else {
		printFlag("DMARC", false, "")
	}
	printFlag("DKIM", res.HasDKIM, res.DKIM)
	printFlag("DNSSEC", res.DNSSEC, "")
	if len(res.CAA) > 0 {
		printFlag("CAA", true, strings.Join(res.CAA, " | "))
	} else {
		printFlag("CAA", false, "нет записей — любой УЦ может выпустить сертификат")
	}
	if len(res.AXFR) > 0 {
		fmt.Println("  Проверка AXFR (передача зоны):")
		for _, h := range res.AXFR {
			mark := "✓"
			if h.Allowed {
				mark = "⚠"
			}
			fmt.Printf("    %s %-24s %s\n", mark, h.NS, h.Note)
		}
	}
	return nil
}

func printFlag(name string, ok bool, detail string) {
	mark := "✗"
	if ok {
		mark = "✓"
	}
	line := fmt.Sprintf("  %s %-8s", mark, name)
	if detail != "" {
		line += " " + detail
	}
	fmt.Println(line)
}

// emitEvents writes one report event per weakness found.
func emitEvents(res Result) {
	emit := func(sev report.Severity, summary string, data map[string]any) {
		_ = report.Emit(report.Event{Tool: "dnssec", Target: res.Domain, Severity: sev, Summary: summary, Data: data})
	}
	if !res.HasSPF {
		emit(report.SeverityMedium, "SPF-запись отсутствует", nil)
	}
	if !res.HasDMARC {
		emit(report.SeverityMedium, "DMARC-запись отсутствует", nil)
	} else if strings.EqualFold(res.DMARCPol, "none") {
		emit(report.SeverityLow, "DMARC policy=none (только мониторинг)", nil)
	}
	if !res.DNSSEC {
		emit(report.SeverityLow, "DNSSEC не включён", nil)
	}
	if len(res.CAA) == 0 {
		emit(report.SeverityLow, "CAA-записи отсутствуют", nil)
	}
	if res.AXFROpen {
		emit(report.SeverityHigh, "разрешена передача зоны (AXFR)", map[string]any{"nameservers": res.Nameservs})
	}
}
