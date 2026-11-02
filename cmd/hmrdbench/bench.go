package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
	"github.com/miekg/dns"
)

// A scenario is a set of resolvers with their limits.
type resolverSpec struct {
	qps     float64
	mode    string
	latency time.Duration // 0: the -latency flag
	loss    float64       // share of queries dropped at random
}

type scenario struct {
	name      string
	resolvers []resolverSpec
}

var scenarios = []scenario{
	{"one-unlimited", []resolverSpec{{qps: 0, mode: "refuse"}}},
	{"one-limited", []resolverSpec{{qps: 30, mode: "refuse"}}},
	{"three-unlimited", []resolverSpec{{mode: "refuse"}, {mode: "refuse"}, {mode: "refuse"}}},
	{"three-limited", []resolverSpec{{qps: 20, mode: "refuse"}, {qps: 30, mode: "refuse"}, {qps: 40, mode: "drop"}}},
	{"three-limited-one-dead", []resolverSpec{{qps: 30, mode: "refuse"}, {qps: 40, mode: "drop"}, {mode: "dead"}}},
	{"three-uneven-latency", []resolverSpec{{mode: "refuse", latency: 20 * time.Millisecond}, {mode: "refuse", latency: 100 * time.Millisecond}, {mode: "refuse", latency: 400 * time.Millisecond}}},
	{"three-lossy", []resolverSpec{{mode: "refuse"}, {mode: "refuse", loss: 0.1}, {mode: "refuse", loss: 0.3}}},
}

// An approach sends one query and calls done once with the answer, or nil.
type approach interface {
	exchange(wire []byte, done func([]byte))
	close()
}

// statser is an approach that can report the pool's per-resolver state.
type statser interface {
	stats() []multidns.ResolverStat
}

func (a *relayApproach) stats() []multidns.ResolverStat { return a.m.Stats() }
func (a *syncApproach) stats() []multidns.ResolverStat  { return a.m.Stats() }

var approaches = []string{"hmrd-auto", "hmrd-roundrobin", "hmrd-sync", "naive-multi", "single"}

func newApproach(name string, addrs []string) (approach, error) {
	switch name {
	case "hmrd-auto", "hmrd-roundrobin":
		lb := multidns.LBAuto
		if name == "hmrd-roundrobin" {
			lb = multidns.LBRoundRobin
		}
		m := multidns.New(multidns.Options{LoadBalance: lb})
		for _, a := range addrs {
			if _, err := m.AddResolverURL(a); err != nil {
				return nil, err
			}
		}
		return &relayApproach{m: m}, nil
	case "hmrd-sync":
		m := multidns.New(multidns.Options{LoadBalance: multidns.LBRoundRobin})
		for _, a := range addrs {
			if _, err := m.AddResolverURL(a); err != nil {
				return nil, err
			}
		}
		return &syncApproach{m: m}, nil
	case "naive-multi":
		return newNaive(addrs)
	case "single":
		return newNaive(addrs[:1])
	}
	return nil, fmt.Errorf("unknown approach %q", name)
}

// relayApproach is the relay (StartLocal, PacketConn and Submit).
type relayApproach struct{ m *multidns.Manager }

func (a *relayApproach) exchange(wire []byte, done func([]byte)) {
	if err := a.m.Submit(wire, done); err != nil {
		done(nil)
	}
}
func (a *relayApproach) close() { _ = a.m.Close() }

// syncApproach is Manager.Resolve, a synchronous exchange per query.
type syncApproach struct{ m *multidns.Manager }

func (a *syncApproach) exchange(wire []byte, done func([]byte)) {
	go func() {
		q := new(dns.Msg)
		if err := q.Unpack(wire); err != nil {
			done(nil)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := a.m.Resolve(ctx, q)
		cancel()
		if err != nil || resp == nil {
			done(nil)
			return
		}
		out, err := resp.Pack()
		if err != nil {
			done(nil)
			return
		}
		done(out)
	}()
}
func (a *syncApproach) close() { _ = a.m.Close() }

// naive is a plain multi-resolver, as most clients have: one socket per
// resolver, round robin, no retry, no rate awareness. With one resolver it is
// the single-resolver baseline.
type naive struct {
	conns []*naiveConn
	next  atomic.Uint64
}

type naiveConn struct {
	conn    net.Conn
	mu      sync.Mutex
	nextID  uint16
	pending map[uint16]naivePending
}

type naivePending struct {
	origID uint16
	done   func([]byte)
	sent   time.Time
}

func newNaive(addrs []string) (*naive, error) {
	n := &naive{}
	for _, a := range addrs {
		c, err := net.Dial("udp", a)
		if err != nil {
			return nil, err
		}
		nc := &naiveConn{conn: c, pending: map[uint16]naivePending{}}
		n.conns = append(n.conns, nc)
		go nc.read()
		go nc.expire()
	}
	return n, nil
}

func (c *naiveConn) read() {
	buf := make([]byte, 65535)
	for {
		k, err := c.conn.Read(buf)
		if err != nil {
			return
		}
		if k < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(buf)
		c.mu.Lock()
		p, ok := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ok {
			out := append([]byte(nil), buf[:k]...)
			binary.BigEndian.PutUint16(out, p.origID)
			p.done(out)
		}
	}
}

func (c *naiveConn) expire() {
	for range time.Tick(100 * time.Millisecond) {
		now := time.Now()
		var dead []naivePending
		c.mu.Lock()
		for id, p := range c.pending {
			if now.Sub(p.sent) > 2*time.Second {
				delete(c.pending, id)
				dead = append(dead, p)
			}
		}
		c.mu.Unlock()
		for _, p := range dead {
			p.done(nil)
		}
	}
}

func (n *naive) exchange(wire []byte, done func([]byte)) {
	c := n.conns[int(n.next.Add(1))%len(n.conns)]
	out := append([]byte(nil), wire...)
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.pending[id] = naivePending{origID: binary.BigEndian.Uint16(wire), done: done, sent: time.Now()}
	c.mu.Unlock()
	binary.BigEndian.PutUint16(out, id)
	if _, err := c.conn.Write(out); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		done(nil)
	}
}

func (n *naive) close() {
	for _, c := range n.conns {
		_ = c.conn.Close()
	}
}

type result struct {
	scenario, approach string
	answered, failed   int64
	duration           time.Duration
	latencies          []time.Duration
}

func (r result) rate() float64 { return float64(r.answered) / r.duration.Seconds() }

func (r result) percentile(p float64) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	sort.Slice(r.latencies, func(i, j int) bool { return r.latencies[i] < r.latencies[j] })
	return r.latencies[int(float64(len(r.latencies)-1)*p)]
}

// run drives an approach with a closed loop of workers, each sending its next
// query when the previous one is answered, like a tunnel's window. After a
// failure a worker waits retryWait from the send, like a tunnel's
// retransmission timer, so instant failures do not turn into a flood.
func run(sc scenario, name string, addrs []string, workers int, duration, retryWait time.Duration, verbose bool) (result, error) {
	ap, err := newApproach(name, addrs)
	if err != nil {
		return result{}, err
	}
	defer ap.close()
	if st, ok := ap.(statser); ok && verbose {
		defer func() {
			for _, s := range st.stats() {
				fmt.Fprintf(os.Stderr, "  %s %s state=%s ok=%d refused=%d timeouts=%d sent=%d cap=%.1f/s latency=%s\n",
					name, s.Name, s.State, s.ValidCount, s.RateLimited, s.TimeoutCount, s.Sent, float64(s.CurrentRPMCap)/60, s.LatencyEWMA.Round(time.Millisecond))
			}
		}()
	}
	res := result{scenario: sc.name, approach: name, duration: duration}
	var answered, failed atomic.Int64
	var latMu sync.Mutex
	stop := time.Now().Add(duration)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var seq uint16
			for time.Now().Before(stop) {
				seq++
				q := new(dns.Msg)
				q.SetQuestion(fmt.Sprintf("q%d-%d.bench.example.", w, seq), dns.TypeA)
				q.Id = uint16(w)<<8 | seq&0xff
				wire, _ := q.Pack()
				ch := make(chan []byte, 1)
				start := time.Now()
				ap.exchange(wire, func(b []byte) {
					select {
					case ch <- b:
					default:
					}
				})
				var resp []byte
				select {
				case resp = <-ch:
				case <-time.After(6 * time.Second):
				}
				if len(resp) >= 12 && resp[3]&0x0F == dns.RcodeSuccess {
					answered.Add(1)
					latMu.Lock()
					res.latencies = append(res.latencies, time.Since(start))
					latMu.Unlock()
				} else {
					failed.Add(1)
					if wait := retryWait - time.Since(start); wait > 0 {
						time.Sleep(wait)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	res.answered, res.failed = answered.Load(), failed.Load()
	return res, nil
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	duration := fs.Duration("duration", 15*time.Second, "length of each run")
	workers := fs.Int("workers", 64, "queries in flight at once (closed loop)")
	latency := fs.Duration("latency", 20*time.Millisecond, "resolver answer delay")
	jitter := fs.Duration("jitter", 10*time.Millisecond, "random extra resolver delay, up to this")
	only := fs.String("scenarios", "", "comma-separated scenarios (default all): "+scenarioNames())
	which := fs.String("approaches", strings.Join(approaches, ","), "comma-separated approaches")
	verbose := fs.Bool("v", false, "print each resolver's state after a pool run (to stderr)")
	retryWait := fs.Duration("retry-wait", 200*time.Millisecond, "after a failed query, a worker waits this long from its send before the next")
	_ = fs.Parse(args)

	var picked []scenario
	for _, sc := range scenarios {
		if *only == "" || strings.Contains(","+*only+",", ","+sc.name+",") {
			picked = append(picked, sc)
		}
	}
	if len(picked) == 0 {
		return errors.New("no scenario selected")
	}

	fmt.Printf("hmrdbench: %d queries in flight, resolver latency %s + up to %s, %s per run, %s retry wait\n\n", *workers, *latency, *jitter, *duration, *retryWait)
	fmt.Println("| Scenario | Approach | Answered/s | Failed | p50 | p95 |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, sc := range picked {
		for _, name := range strings.Split(*which, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			// fresh resolvers for every run, so no run inherits another's state
			var servers []*limitedResolver
			var addrs []string
			for _, spec := range sc.resolvers {
				s := newLimitedResolver(spec.qps, spec.mode)
				s.latency, s.jitter, s.loss = *latency, *jitter, spec.loss
				if spec.latency > 0 {
					s.latency = spec.latency
				}
				addr, err := s.start("127.0.0.1:0")
				if err != nil {
					return err
				}
				servers = append(servers, s)
				addrs = append(addrs, addr)
			}
			r, err := run(sc, name, addrs, *workers, *duration, *retryWait, *verbose)
			for _, s := range servers {
				s.stop()
			}
			if err != nil {
				return err
			}
			fmt.Printf("| %s | %s | %.1f | %d | %s | %s |\n", sc.name, name, r.rate(), r.failed,
				r.percentile(0.5).Round(time.Millisecond), r.percentile(0.95).Round(time.Millisecond))
			_ = os.Stdout.Sync()
		}
	}
	return nil
}

func scenarioNames() string {
	var names []string
	for _, sc := range scenarios {
		names = append(names, sc.name)
	}
	return strings.Join(names, ", ")
}
