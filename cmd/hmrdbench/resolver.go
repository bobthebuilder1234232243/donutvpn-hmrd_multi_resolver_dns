package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// limitedResolver is a UDP+TCP DNS server that serves up to qps queries a
// second (token bucket, one second of burst; 0 = unlimited) and refuses or
// drops the rest. It answers names under a route's domain by forwarding to
// that route's server (a DNS tunnel server), and every other name either by
// forwarding to public or, when public is empty, with a local A record after
// latency (plus up to jitter).
type limitedResolver struct {
	qps     float64
	mode    string // refuse, drop or dead
	routes  map[string]string
	public  string
	latency time.Duration
	jitter  time.Duration
	loss    float64 // share of queries dropped at random

	mu     sync.Mutex
	tokens float64
	last   time.Time

	served  atomic.Int64
	limited atomic.Int64

	client  *dns.Client
	servers []*dns.Server
}

func newLimitedResolver(qps float64, mode string) *limitedResolver {
	return &limitedResolver{
		qps:    qps,
		mode:   mode,
		routes: map[string]string{},
		tokens: qps,
		last:   time.Now(),
		client: &dns.Client{Net: "udp", Timeout: 4 * time.Second, UDPSize: 4096},
	}
}

func (s *limitedResolver) take() bool {
	if s.qps <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.tokens += now.Sub(s.last).Seconds() * s.qps
	if s.tokens > s.qps {
		s.tokens = s.qps
	}
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

func (s *limitedResolver) handle(w dns.ResponseWriter, r *dns.Msg) {
	if s.mode == "dead" || (s.loss > 0 && rand.Float64() < s.loss) { //nolint:gosec
		s.limited.Add(1)
		return
	}
	if !s.take() {
		s.limited.Add(1)
		if s.mode == "drop" {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	upstream := s.public
	if len(r.Question) > 0 {
		name := strings.ToLower(r.Question[0].Name)
		for suffix, addr := range s.routes {
			if strings.HasSuffix(name, suffix) {
				upstream = addr
			}
		}
	}
	answer := func() {
		if upstream != "" {
			resp, _, err := s.client.Exchange(r, upstream)
			if err != nil {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				_ = w.WriteMsg(m)
				return
			}
			s.served.Add(1)
			_ = w.WriteMsg(resp)
			return
		}
		s.served.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	}
	// the latency applies to forwarded queries too, so a tunnel can be
	// tested over a slow resolver
	delay := s.latency
	if s.jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(s.jitter))) //nolint:gosec
	}
	if delay <= 0 {
		if upstream != "" {
			go answer() // a tunnel server may hold the query: do not block the reader
			return
		}
		answer()
		return
	}
	time.AfterFunc(delay, answer)
}

// start listens on addr (UDP and TCP; port 0 picks a free one) and returns
// the UDP address.
func (s *limitedResolver) start(addr string) (string, error) {
	var pc net.PacketConn
	var ln net.Listener
	var bound string
	for try := 0; ; try++ {
		var err error
		pc, err = net.ListenPacket("udp", addr)
		if err != nil {
			return "", err
		}
		bound = pc.LocalAddr().String()
		ln, err = net.Listen("tcp", bound)
		if err == nil {
			break
		}
		_ = pc.Close()
		// a free UDP port can be taken on TCP; with port 0, pick another
		if !strings.HasSuffix(addr, ":0") || try > 10 {
			return "", err
		}
	}
	handler := dns.HandlerFunc(s.handle)
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: ln, Handler: handler}
	s.servers = []*dns.Server{udp, tcp}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	return bound, nil
}

func (s *limitedResolver) stop() {
	for _, srv := range s.servers {
		_ = srv.Shutdown()
	}
}

func runResolver(args []string) error {
	fs := flag.NewFlagSet("resolver", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:5300", "address to listen on (UDP and TCP)")
	qps := fs.Float64("qps", 0, "queries per second served; 0 = unlimited")
	mode := fs.String("mode", "refuse", "over the limit: refuse (REFUSED) or drop (no answer); dead: never answer")
	public := fs.String("public", "", "resolver for names outside every -route; empty answers them locally")
	latency := fs.Duration("latency", 0, "delay of every answer, forwarded or local")
	jitter := fs.Duration("jitter", 0, "random extra delay of every answer, up to this")
	loss := fs.Float64("loss", 0, "share of queries dropped at random, 0 to 1")
	stats := fs.Duration("stats", 10*time.Second, "how often to log the counters; 0 = never")
	routes := map[string]string{}
	fs.Func("route", "domain=addr: forward names under domain to addr (repeatable), e.g. t.example.com=127.0.0.1:5353", func(v string) error {
		d, a, ok := strings.Cut(v, "=")
		if !ok {
			return errors.New("want domain=addr")
		}
		routes[strings.ToLower(dns.Fqdn(d))] = a
		return nil
	})
	_ = fs.Parse(args)
	switch *mode {
	case "refuse", "drop", "dead":
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
	s := newLimitedResolver(*qps, *mode)
	s.routes, s.public, s.latency, s.jitter, s.loss = routes, *public, *latency, *jitter, *loss
	addr, err := s.start(*listen)
	if err != nil {
		return err
	}
	log.Printf("resolver on %s qps=%g mode=%s routes=%v", addr, *qps, *mode, routes)
	if *stats > 0 {
		for range time.Tick(*stats) {
			log.Printf("%s: served=%d limited=%d", addr, s.served.Load(), s.limited.Load())
		}
	}
	select {}
}
