package multidns

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// limitedServer is a UDP DNS server that answers up to qps queries per second
// (0 = unlimited) and refuses or drops the rest; dead drops everything.
type limitedServer struct {
	addr    string
	qps     float64
	drop    bool
	dead    atomic.Bool
	served  atomic.Int64
	limited atomic.Int64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func startLimited(t *testing.T, qps float64, drop bool) *limitedServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &limitedServer{addr: pc.LocalAddr().String(), qps: qps, drop: drop, tokens: qps, last: time.Now()}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.handle)}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return s
}

func (s *limitedServer) take() bool {
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

func (s *limitedServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	if s.dead.Load() {
		return
	}
	if !s.take() {
		s.limited.Add(1)
		if s.drop {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	s.served.Add(1)
	m := new(dns.Msg)
	m.SetReply(r)
	rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
	m.Answer = append(m.Answer, rr)
	_ = w.WriteMsg(m)
}

func wireQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = id
	out, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// submitWait sends one query through the relay and waits for its answer.
func submitWait(t *testing.T, m *Manager, id uint16, name string, wait time.Duration) *dns.Msg {
	t.Helper()
	ch := make(chan []byte, 1)
	if err := m.Submit(wireQuery(t, id, name), func(resp []byte) { ch <- resp }); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-ch:
		msg := new(dns.Msg)
		if err := msg.Unpack(resp); err != nil {
			t.Fatal(err)
		}
		return msg
	case <-time.After(wait):
		return nil
	}
}

func statByAddr(m *Manager, addr string) ResolverStat {
	for _, info := range m.Resolvers() {
		if info.Address == addr {
			for _, st := range m.Stats() {
				if st.ID == info.ID {
					return st
				}
			}
		}
	}
	return ResolverStat{}
}

// The answer comes back with the client's ID, over one long-lived socket.
func TestRelayAnswersWithClientID(t *testing.T) {
	s := startLimited(t, 0, false)
	m := New(Options{LoadBalance: LBAuto})
	defer m.Close()
	if _, err := m.AddResolverURL(s.addr); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		resp := submitWait(t, m, uint16(1000+i), "a.test", 2*time.Second)
		if resp == nil || resp.Id != uint16(1000+i) || len(resp.Answer) != 1 {
			t.Fatalf("query %d: %v", i, resp)
		}
	}
	if err := m.Submit([]byte{1, 2, 3}, func([]byte) {}); err == nil {
		t.Fatal("short packet accepted")
	}
}

// A REFUSED answer is retried at once on another resolver.
func TestRelayRetriesRefusedOnAnotherResolver(t *testing.T) {
	refusing := startLimited(t, 0.001, false) // never has a whole token: refuses everything
	ok := startLimited(t, 0, false)
	m := New(Options{LoadBalance: LBRoundRobin})
	defer m.Close()
	_, _ = m.AddResolverURL(ok.addr)
	_, _ = m.AddResolverURL(refusing.addr) // round robin tries it first
	start := time.Now()
	resp := submitWait(t, m, 7, "a.test", 2*time.Second)
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("no answer after the refusal: %v", resp)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("the retry waited: %s", d)
	}
	if refusing.limited.Load() == 0 || ok.served.Load() == 0 {
		t.Fatalf("refused %d, served %d", refusing.limited.Load(), ok.served.Load())
	}
}

// A dead resolver: queries move to the live one, the dead one goes down,
// gets a copy of live queries as probes, and comes back once it answers.
func TestRelayDownResolverIsProbedAndRecovers(t *testing.T) {
	dead := startLimited(t, 0, false)
	dead.dead.Store(true)
	live := startLimited(t, 0, false)
	m := New(Options{LoadBalance: LBRoundRobin, DefaultResolverTimeout: 300 * time.Millisecond, DownAfterFailures: 3, RelayProbeInterval: 100 * time.Millisecond})
	defer m.Close()
	_, _ = m.AddResolverURL(live.addr)
	_, _ = m.AddResolverURL(dead.addr)
	for i := 0; i < 30; i++ {
		if resp := submitWait(t, m, uint16(i), "a.test", 3*time.Second); resp == nil || resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d: %v", i, resp)
		}
	}
	if st := statByAddr(m, dead.addr); st.State != "down" {
		t.Fatalf("dead resolver not down: %+v", st)
	}
	dead.dead.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		submitWait(t, m, 1, "b.test", time.Second)
		if st := statByAddr(m, dead.addr); st.State == "healthy" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("not back after it answered: %+v", statByAddr(m, dead.addr))
}

// SpreadCount -1 sends every query to every resolver.
func TestRelayFanout(t *testing.T) {
	a := startLimited(t, 0, false)
	b := startLimited(t, 0, false)
	m := New(Options{LoadBalance: LBAuto, SpreadCount: -1})
	defer m.Close()
	_, _ = m.AddResolverURL(a.addr)
	_, _ = m.AddResolverURL(b.addr)
	for i := 0; i < 10; i++ {
		if resp := submitWait(t, m, uint16(i), "a.test", 2*time.Second); resp == nil {
			t.Fatal("no answer")
		}
	}
	time.Sleep(100 * time.Millisecond)
	if a.served.Load() < 10 || b.served.Load() < 10 {
		t.Fatalf("not sent to both: %d %d", a.served.Load(), b.served.Load())
	}
}

// burst sends n queries at rate qps through the relay and returns how many
// got a successful answer.
func burst(t *testing.T, m *Manager, n int, qps float64) int {
	t.Helper()
	var okCount atomic.Int64
	var wg sync.WaitGroup
	interval := time.Duration(float64(time.Second) / qps)
	for i := 0; i < n; i++ {
		wg.Add(1)
		q := wireQuery(t, uint16(i), "x.test")
		_ = m.Submit(q, func(resp []byte) {
			if len(resp) >= 12 && resp[3]&0x0F == dns.RcodeSuccess {
				okCount.Add(1)
			}
			wg.Done()
		})
		time.Sleep(interval)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return int(okCount.Load())
}

// Two limited resolvers (20 and 60 queries per second): with LBAuto the
// relay learns both caps and puts about three times as many queries on the
// larger one, so almost every query of a 70 per second stream is answered.
func TestRelayLearnsCapacityAndSpreadsByIt(t *testing.T) {
	small := startLimited(t, 20, false)
	large := startLimited(t, 60, false)
	m := New(Options{LoadBalance: LBAuto})
	defer m.Close()
	_, _ = m.AddResolverURL(small.addr)
	_, _ = m.AddResolverURL(large.addr)
	ok := burst(t, m, 420, 70) // 6 s
	if ok < 400 {
		t.Fatalf("only %d of 420 answered (small %d/%d, large %d/%d)", ok, small.served.Load(), small.limited.Load(), large.served.Load(), large.limited.Load())
	}
	if large.served.Load() < 2*small.served.Load() {
		t.Fatalf("not spread by capacity: small %d, large %d", small.served.Load(), large.served.Load())
	}
}

// One resolver limited to 30 per second, fed 25 per second after learning:
// the cap keeps refusals rare instead of hitting the limit all the time.
func TestRelayPacesUnderOneLimitedResolver(t *testing.T) {
	s := startLimited(t, 30, false)
	m := New(Options{LoadBalance: LBAuto})
	defer m.Close()
	_, _ = m.AddResolverURL(s.addr)
	ok := burst(t, m, 200, 25)
	if ok < 190 {
		t.Fatalf("only %d of 200 answered (served %d, refused %d)", ok, s.served.Load(), s.limited.Load())
	}
}

// A resolver that drops queries over its limit loses traffic to its healthy
// peer (its loss raises its cost, and a run of drops caps it), and every
// query is still answered.
func TestRelaySilentDropperIsCapped(t *testing.T) {
	dropper := startLimited(t, 15, true)
	ok := startLimited(t, 0, false)
	m := New(Options{LoadBalance: LBAuto, DefaultResolverTimeout: 500 * time.Millisecond})
	defer m.Close()
	_, _ = m.AddResolverURL(dropper.addr)
	_, _ = m.AddResolverURL(ok.addr)
	answered := burst(t, m, 300, 60)
	if answered < 290 {
		t.Fatalf("only %d of 300 answered", answered)
	}
	st := statByAddr(m, dropper.addr)
	if st.Sent == 0 {
		t.Fatalf("dropper never sampled: %+v", st)
	}
	if dropper.served.Load() >= ok.served.Load() {
		t.Fatalf("dropper kept the larger share: %d vs %d", dropper.served.Load(), ok.served.Load())
	}
}

// The relay dials UDP through the resolver's Dialer.
func TestRelayUsesDialer(t *testing.T) {
	s := startLimited(t, 0, false)
	var dialed atomic.Int64
	m := New(Options{})
	defer m.Close()
	_, err := m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: s.addr, Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if resp := submitWait(t, m, uint16(i), "a.test", 2*time.Second); resp == nil {
			t.Fatal("no answer")
		}
	}
	if dialed.Load() != 1 {
		t.Fatalf("dialed %d times, want one long-lived socket", dialed.Load())
	}
}

// A query no resolver answers ends with SERVFAIL carrying the client's ID.
func TestRelayFailsWithServfail(t *testing.T) {
	s := startLimited(t, 0, false)
	s.dead.Store(true)
	m := New(Options{DefaultResolverTimeout: 200 * time.Millisecond, DefaultDeadline: time.Second})
	defer m.Close()
	_, _ = m.AddResolverURL(s.addr)
	resp := submitWait(t, m, 4242, "a.test", 3*time.Second)
	if resp == nil || resp.Rcode != dns.RcodeServerFailure || resp.Id != 4242 {
		t.Fatalf("got %v", resp)
	}
}

// The local listener relays raw UDP.
func TestRelayThroughLocalListener(t *testing.T) {
	s := startLimited(t, 0, false)
	m, addr, err := StartLocal(Options{LoadBalance: LBAuto})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, _ = m.AddResolverURL(s.addr)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 50; i++ {
		if _, err := conn.Write(wireQuery(t, uint16(500+i), "l.test")); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	seen := map[uint16]bool{}
	for len(seen) < 50 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("got %d of 50: %v", len(seen), err)
		}
		seen[binary.BigEndian.Uint16(buf[:n])] = true
	}
}

// A resolver that silently drops what exceeds its limit stays in service
// with a cap; only a resolver with no answer at all goes down.
func TestRelaySilentDropperIsNotTakenDown(t *testing.T) {
	dropper := startLimited(t, 30, true)
	m := New(Options{LoadBalance: LBAuto, DefaultResolverTimeout: 400 * time.Millisecond, DownAfterFailures: 3})
	defer m.Close()
	_, _ = m.AddResolverURL(dropper.addr)
	burst(t, m, 240, 60) // twice its limit for 4 s
	st := statByAddr(m, dropper.addr)
	if st.State == "down" {
		t.Fatalf("a resolver answering half its queries was taken down: %+v", st)
	}
	if st.TimeoutCount < 3 {
		t.Fatalf("the test did not overload it: %+v", st)
	}
}

// startDelayed is an unlimited resolver that answers after delay.
func startDelayed(t *testing.T, delay time.Duration, served *atomic.Int64) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.AfterFunc(delay, func() {
			served.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
		})
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// LBAuto gives an unlimited fast resolver the traffic instead of spreading it
// evenly over a slow one, while still sampling the slow one now and then.
func TestRelayAutoPrefersFastResolver(t *testing.T) {
	var fastServed, slowServed atomic.Int64
	fast := startDelayed(t, 5*time.Millisecond, &fastServed)
	slow := startDelayed(t, 150*time.Millisecond, &slowServed)
	m := New(Options{LoadBalance: LBAuto})
	defer m.Close()
	_, _ = m.AddResolverURL(slow)
	_, _ = m.AddResolverURL(fast)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				submitWait(t, m, uint16(w*100+i), "p.test", 2*time.Second)
			}
		}(w)
	}
	wg.Wait()
	if slowServed.Load() == 0 {
		t.Fatal("the slow resolver was never sampled")
	}
	if fastServed.Load() < 10*slowServed.Load() {
		t.Fatalf("traffic not concentrated on the fast resolver: fast %d, slow %d", fastServed.Load(), slowServed.Load())
	}
}
