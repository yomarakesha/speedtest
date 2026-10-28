// Package trace is a traceroute + continuous-ping engine that produces an
// mtr/trippy-style hop table: for every hop on the path it tracks sent/received
// counts, last/avg/best/worst RTT and loss%. It re-probes the whole path on a
// loop so the stats stay live.
//
// ICMP is sent without administrator/root rights via a platform-specific probe:
//   - Windows: the IP Helper API (IcmpSendEcho) in trace_windows.go
//   - Unix:    unprivileged ICMP datagram sockets in trace_unix.go
//
// Both implement probeHop; this file owns the resolve + TTL-walk loop and the
// statistics, so behavior is identical across platforms.
package trace

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Options configures a trace run.
type Options struct {
	Host     string        // target host or IP
	MaxHops  int           // TTL ceiling (default 30)
	Timeout  time.Duration // per-probe timeout (default 1s)
	Interval time.Duration // pause between full rounds (default 1s)
	Rounds   int           // stop after N full rounds (0 = until ctx is canceled)
}

// Hop is the accumulated statistics for one TTL position on the path.
type Hop struct {
	TTL     int     `json:"ttl"`
	Host    string  `json:"host,omitempty"` // responding IP ("" = no reply yet)
	Name    string  `json:"name,omitempty"` // reverse DNS, if resolved
	Sent    int     `json:"sent"`
	Recv    int     `json:"recv"`
	LossPct float64 `json:"loss_pct"`
	LastMs  float64 `json:"last_ms"`
	AvgMs   float64 `json:"avg_ms"`
	BestMs  float64 `json:"best_ms"`
	WorstMs float64 `json:"worst_ms"`

	sum float64
}

// hopReply is what a single platform probe returns.
type hopReply struct {
	from    net.IP        // router/host that replied (nil on timeout)
	rtt     time.Duration // measured round-trip
	reached bool          // true when the reply came from the destination
	err     error         // transport error (nil on timeout — that is just loss)
}

// Trace resolves Host and walks the path repeatedly, calling cb (may be nil)
// with a fresh snapshot of the hop table after every probe. It runs until ctx
// is canceled. The destination is discovered dynamically; once a hop reaches it,
// later rounds stop at that TTL.
func Trace(ctx context.Context, opt Options, cb func([]Hop)) error {
	if opt.MaxHops <= 0 {
		opt.MaxHops = 30
	}
	if opt.Timeout <= 0 {
		opt.Timeout = time.Second
	}
	if opt.Interval <= 0 {
		opt.Interval = time.Second
	}

	ipAddr, err := net.ResolveIPAddr("ip4", opt.Host)
	if err != nil {
		return fmt.Errorf("не удалось разрешить %q: %w", opt.Host, err)
	}
	dst := ipAddr.IP

	hops := map[int]*Hop{}
	var order []int
	reachedAt := 0
	names := newResolver()

	emit := func() {
		if cb == nil {
			return
		}
		snap := make([]Hop, 0, len(order))
		for _, ttl := range order {
			h := hops[ttl]
			if n := names.get(h.Host); n != "" {
				h.Name = n
			}
			snap = append(snap, *h)
		}
		sort.Slice(snap, func(i, j int) bool { return snap[i].TTL < snap[j].TTL })
		cb(snap)
	}

	for round := 1; ; round++ {
		limit := opt.MaxHops
		if reachedAt > 0 {
			limit = reachedAt
		}
		for ttl := 1; ttl <= limit; ttl++ {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			h := hops[ttl]
			if h == nil {
				h = &Hop{TTL: ttl}
				hops[ttl] = h
				order = append(order, ttl)
			}
			h.Sent++

			r := probeHop(dst, ttl, opt.Timeout)
			if r.err == nil && r.from != nil {
				h.Recv++
				ms := r.rtt.Seconds() * 1000
				h.LastMs = ms
				h.sum += ms
				if h.BestMs == 0 || ms < h.BestMs {
					h.BestMs = ms
				}
				if ms > h.WorstMs {
					h.WorstMs = ms
				}
				h.AvgMs = h.sum / float64(h.Recv)
				h.Host = r.from.String()
				names.request(h.Host)
				if r.reached && reachedAt == 0 {
					reachedAt = ttl
				}
			}
			h.LossPct = float64(h.Sent-h.Recv) / float64(h.Sent) * 100
			emit()

			// Once any hop reaches the destination, the path is fully known;
			// stop this round so we don't probe TTLs beyond it.
			if reachedAt > 0 && ttl >= reachedAt {
				break
			}
		}

		if opt.Rounds > 0 && round >= opt.Rounds {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opt.Interval):
		}
	}
}

// resolver does best-effort reverse DNS in the background so the probe loop
// never blocks on it. Results are cached by IP.
type resolver struct {
	mu       sync.Mutex
	names    map[string]string
	inflight map[string]bool
}

func newResolver() *resolver {
	return &resolver{names: map[string]string{}, inflight: map[string]bool{}}
}

func (r *resolver) get(ip string) string {
	if ip == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names[ip]
}

func (r *resolver) request(ip string) {
	if ip == "" {
		return
	}
	r.mu.Lock()
	if r.inflight[ip] || r.names[ip] != "" {
		r.mu.Unlock()
		return
	}
	r.inflight[ip] = true
	r.mu.Unlock()

	go func() {
		var name string
		if hosts, err := net.LookupAddr(ip); err == nil && len(hosts) > 0 {
			name = trimDot(hosts[0])
		}
		r.mu.Lock()
		if name != "" {
			r.names[ip] = name
		}
		delete(r.inflight, ip)
		r.mu.Unlock()
	}()
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
