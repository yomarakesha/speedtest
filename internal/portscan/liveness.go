package portscan

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// livenessPorts are probed to decide if a host is up. A connection that either
// succeeds or is actively refused proves the host exists; only when every probe
// times out (or is dropped) is the host treated as down.
var livenessPorts = []int{80, 443, 22, 445, 3389, 139, 53, 8080, 135}

// hostAlive returns true if the host answers (accept or refuse) on any
// liveness port within timeout.
func hostAlive(host string, timeout time.Duration) bool {
	ch := make(chan bool, len(livenessPorts))
	for _, p := range livenessPorts {
		go func(port int) {
			addr := net.JoinHostPort(host, fmt.Sprint(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				ch <- true
				return
			}
			ch <- isRefused(err) // refused == host is up
		}(p)
	}
	for range livenessPorts {
		if <-ch {
			return true
		}
	}
	return false
}

// isRefused reports whether a dial error is a TCP RST (connection refused),
// which means the host is reachable but the port is closed.
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

// filterAlive probes every host concurrently (bounded by workers) and returns
// only those that are up.
func filterAlive(hosts []string, timeout time.Duration, workers int) []string {
	if workers < 1 {
		workers = 1
	}
	type res struct {
		host  string
		alive bool
	}
	sem := make(chan struct{}, workers)
	out := make(chan res, len(hosts))

	for _, h := range hosts {
		sem <- struct{}{}
		go func(host string) {
			defer func() { <-sem }()
			out <- res{host, hostAlive(host, timeout)}
		}(h)
	}

	alive := make([]string, 0, len(hosts))
	for range hosts {
		r := <-out
		if r.alive {
			alive = append(alive, r.host)
		}
	}
	return alive
}
