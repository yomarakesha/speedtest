package audit

import (
	"context"
	"fmt"
	"time"

	"speedtest/internal/portscan"
)

// riskyPort describes a port whose exposure warrants a finding, with the
// severity reflecting how dangerous it typically is to reach from an untrusted
// network.
type riskyPort struct {
	sev  Severity
	name string
}

// riskyPorts are services that should rarely be exposed beyond a trusted LAN.
var riskyPorts = map[int]riskyPort{
	23:    {High, "Telnet (незашифрованный удалённый доступ)"},
	445:   {High, "SMB (общий доступ к файлам Windows)"},
	3389:  {High, "RDP (удалённый рабочий стол)"},
	5900:  {High, "VNC (удалённый рабочий стол)"},
	6379:  {High, "Redis (часто без аутентификации)"},
	27017: {High, "MongoDB (часто без аутентификации)"},
	9200:  {High, "Elasticsearch (часто без аутентификации)"},
	135:   {Medium, "MS RPC"},
	139:   {Medium, "NetBIOS"},
	21:    {Medium, "FTP (незашифрованная передача файлов)"},
	1433:  {Medium, "MS SQL Server"},
	3306:  {Medium, "MySQL"},
	5432:  {Medium, "PostgreSQL"},
	11211: {Medium, "Memcached"},
}

// auditPortsList is the set of ports probed by the exposure check.
var auditPortsList = func() []int {
	ports := make([]int, 0, len(riskyPorts))
	for p := range riskyPorts {
		ports = append(ports, p)
	}
	return ports
}()

// AuditPorts scans host for exposed risky services and returns a finding for
// each open one. It only reports ports it recognizes as sensitive.
func AuditPorts(host string, timeout time.Duration) []Finding {
	res := portscan.ScanLive(context.Background(), portscan.ScanOptions{
		Host: host, Ports: auditPortsList, Timeout: timeout, Workers: len(auditPortsList),
	}, nil, nil)

	// A host that accepts nearly every probed port (CDN edge, load balancer or
	// firewall tarpit) makes a connect scan meaningless — suppress rather than
	// emit a wall of false positives.
	if len(auditPortsList) > 0 && len(res.Open)*100 >= len(auditPortsList)*80 {
		return []Finding{{
			Check: "port.scan_unreliable", Severity: Info,
			Title:  "Скан портов ненадёжен",
			Detail: "хост отвечает почти на все порты (CDN/балансировщик/фаервол); проверка пропущена",
		}}
	}

	var out []Finding
	for _, p := range res.Open {
		rp, ok := riskyPorts[p.Port]
		if !ok {
			continue
		}
		out = append(out, Finding{
			Check:    "port.risky_exposed",
			Severity: rp.sev,
			Title:    fmt.Sprintf("Открыт чувствительный порт %d/%s", p.Port, portscan.ServiceName(p.Port)),
			Detail:   rp.name,
		})
	}
	return out
}
