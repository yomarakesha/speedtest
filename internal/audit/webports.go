package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"speedtest/internal/portscan"
)

// commonWebPorts are ports that frequently host an HTTP(S) service. The audit
// probes every one and audits whichever answer, so a host serving its app on
// 8000/8080/9000 (uvicorn, SPA, MinIO, Gitea, ...) is covered — not just 443.
var commonWebPorts = []int{
	80, 443, 591, 2375, 2376, 3000, 4443, 5000, 5601, 7001, 7002,
	8000, 8008, 8080, 8081, 8088, 8090, 8180, 8443, 8834, 8888,
	9000, 9001, 9002, 9090, 9200, 9443, 15672, 16080,
}

// tlsWebPorts hints which discovered ports should be tried as https first. Other
// ports are tried http first; either way auditWebService retries the alternate
// scheme once, so a misplaced service is still assessed.
var tlsWebPorts = map[int]bool{
	443: true, 4443: true, 8443: true, 8834: true, 9443: true, 16080: true,
}

// webService is one reachable HTTP(S) endpoint discovered on the host.
type webService struct {
	port   int
	scheme string
}

// discoverWebServices scans the host's common web ports and returns each open
// one, guessing the scheme from the port number.
func discoverWebServices(host string, timeout time.Duration) []webService {
	if timeout <= 0 {
		timeout = time.Second
	}
	res := portscan.ScanLive(context.Background(), portscan.ScanOptions{
		Host: host, Ports: commonWebPorts, Timeout: timeout, Workers: len(commonWebPorts),
	}, nil, nil)

	var svcs []webService
	for _, p := range res.Open {
		scheme := "http"
		if tlsWebPorts[p.Port] {
			scheme = "https"
		}
		svcs = append(svcs, webService{port: p.Port, scheme: scheme})
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].port < svcs[j].port })
	return svcs
}

// auditWebService audits one discovered endpoint: security headers, sensitive
// paths, and — for an https service — the TLS configuration. Every finding is
// tagged with the origin port so a host running several web services reads
// unambiguously in one report.
func auditWebService(host string, s webService, timeout time.Duration) []Finding {
	url := fmt.Sprintf("%s://%s:%d", s.scheme, host, s.port)

	hf, err := AuditHTTP(url, timeout)
	if err != nil {
		// Scheme guess may be wrong (e.g. plain HTTP on a "tls" port, or TLS on a
		// bare port). Retry the alternate scheme, but only adopt it when it
		// actually succeeds — otherwise keep the original scheme so the path/TLS
		// checks below still run against the port's true nature.
		alt := fmt.Sprintf("%s://%s:%d", altScheme(s.scheme), host, s.port)
		if hf2, err2 := AuditHTTP(alt, timeout); err2 == nil {
			url, hf, err = alt, hf2, nil
		}
	}

	var out []Finding
	if err == nil {
		out = append(out, hf...)
	}
	out = append(out, AuditWebPaths(url, timeout)...)
	if strings.HasPrefix(url, "https://") {
		if tf, err := AuditTLS(host, s.port, timeout); err == nil {
			out = append(out, tf...)
		}
	}
	return tagPort(out, s.port)
}

// altScheme returns the other web scheme.
func altScheme(scheme string) string {
	if scheme == "https" {
		return "http"
	}
	return "https"
}

// tagPort prefixes each finding's title with its origin port so identical checks
// from different services stay distinct, and records the port as evidence when
// the check didn't set its own.
func tagPort(fs []Finding, port int) []Finding {
	for i := range fs {
		fs[i].Title = fmt.Sprintf("[:%d] %s", port, fs[i].Title)
		if fs[i].Evidence == "" {
			fs[i].Evidence = fmt.Sprintf("port %d", port)
		}
	}
	return fs
}
