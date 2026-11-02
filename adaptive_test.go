package multidns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startBehaviourServer answers every query with an A record, unless mode says
// to drop it (no answer) or refuse it.
func startBehaviourServer(t *testing.T, mode *atomic.Int32, served *atomic.Int64) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		switch mode.Load() {
		case 1: // drop
			return
		case 2: // refuse
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		served.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// A resolver that drops packets costs a hedge delay, not its whole timeout:
// the second resolver answers while the first is still waiting, and the
// first is not charged a timeout for the cancelled attempt.
func TestHedgingCoversDroppingResolver(t *testing.T) {
	var dropMode, okMode atomic.Int32
	var dropServed, okServed atomic.Int64
	dropMode.Store(1)
	dropAddr := startBehaviourServer(t, &dropMode, &dropServed)
	okAddr := startBehaviourServer(t, &okMode, &okServed)

	m := New(Options{DefaultResolverTimeout: 2 * time.Second, HedgeDelay: 150 * time.Millisecond, LoadBalance: LBRoundRobin})
	defer m.Close()
	// round robin rotates by one before the first query, so the second
	// resolver added (the dropper) is tried first
	if _, err := m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: okAddr}); err != nil {
		t.Fatal(err)
	}
	dropID, _ := m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: dropAddr})
	start := time.Now()
	resp, err := m.Resolve(context.Background(), query("a.test"))
	if err != nil || len(resp.Answer) != 1 {
		t.Fatalf("resolve: %v %v", err, resp)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("hedging did not cover the dropper: took %s", d)
	}
	if okServed.Load() == 0 {
		t.Fatal("the healthy resolver did not answer")
	}
	for _, stat := range m.Stats() {
		if stat.ID == dropID && stat.TimeoutCount != 0 {
			t.Fatalf("the cancelled hedge was charged as a timeout: %+v", stat)
		}
	}
}

// With the adaptive delay, a resolver is hedged only once it has lost a
// packet: the first query to a fresh dropper waits its (short, adaptive)
// timeout, the next ones are covered after a hedge delay.
func TestAdaptiveHedgingAfterLoss(t *testing.T) {
	var dropMode, okMode atomic.Int32
	var served atomic.Int64
	dropMode.Store(1)
	dropAddr := startBehaviourServer(t, &dropMode, &served)
	okAddr := startBehaviourServer(t, &okMode, &served)
	m := New(Options{DefaultResolverTimeout: 600 * time.Millisecond, LoadBalance: LBRoundRobin})
	defer m.Close()
	_, _ = m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: okAddr})
	dropID, _ := m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: dropAddr}) // tried first on odd queries

	start := time.Now()
	if _, err := m.Resolve(context.Background(), query("first.test")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Fatalf("a resolver with no loss history was hedged early: %s", d)
	}
	for _, st := range m.Stats() {
		if st.ID == dropID && st.TimeoutCount != 1 {
			t.Fatalf("the first loss was not charged: %+v", st)
		}
	}
	// query 2 goes to ok first; query 3 to the dropper again, now known lossy
	_, _ = m.Resolve(context.Background(), query("second.test"))
	start = time.Now()
	if _, err := m.Resolve(context.Background(), query("third.test")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 450*time.Millisecond {
		t.Fatalf("a lossy resolver was not hedged: %s", d)
	}
}

// With hedging off, attempts are sequential and the dropper costs its timeout.
func TestHedgingDisabledIsSequential(t *testing.T) {
	var dropMode, okMode atomic.Int32
	var served atomic.Int64
	dropMode.Store(1)
	dropAddr := startBehaviourServer(t, &dropMode, &served)
	okAddr := startBehaviourServer(t, &okMode, &served)
	m := New(Options{DefaultResolverTimeout: 400 * time.Millisecond, DisableHedging: true, DisableAdaptiveTimeout: true, LoadBalance: LBRoundRobin})
	defer m.Close()
	_, _ = m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: okAddr})
	_, _ = m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: dropAddr}) // tried first, see above
	start := time.Now()
	if _, err := m.Resolve(context.Background(), query("a.test")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Fatalf("sequential attempt returned before the dropper's timeout: %s", d)
	}
}

// The cap after a refusal follows the measured success rate and recovers
// within seconds, not minutes.
func TestRateLimitFollowsSuccessRateAndRecoversFast(t *testing.T) {
	var mode atomic.Int32
	var served atomic.Int64
	addr := startBehaviourServer(t, &mode, &served)
	m := New(Options{RateLimitFloorRPM: 6, RateLimitRecoveryInterval: 200 * time.Millisecond, RateLimitUncapAfter: 1500 * time.Millisecond, RateLimitUncapRPM: 0})
	defer m.Close()
	id, _ := m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: addr})
	statOf := func() ResolverStat {
		for _, s := range m.Stats() {
			if s.ID == id {
				return s
			}
		}
		t.Fatal("no stat")
		return ResolverStat{}
	}

	// 40 successes within the window set the rate the cap is derived from
	for i := 0; i < 40; i++ {
		if _, err := m.Resolve(context.Background(), query("ok.test")); err != nil {
			t.Fatal(err)
		}
	}
	mode.Store(2)
	_, _ = m.Resolve(context.Background(), query("refused.test"))
	st := statOf()
	if st.State != "rate_limited" || st.CurrentRPMCap == 0 {
		t.Fatalf("not rate limited: %+v", st)
	}
	// 40 answers in about a second: 0.75 of that per minute is in the hundreds, not 20
	if st.CurrentRPMCap < 100 {
		t.Fatalf("cap %d does not follow the success rate", st.CurrentRPMCap)
	}
	firstCap := st.CurrentRPMCap

	// a second refusal within the recovery interval does not halve again
	_, _ = m.Resolve(context.Background(), query("refused2.test"))
	if st = statOf(); st.CurrentRPMCap < firstCap*3/4-1 {
		t.Fatalf("burst of refusals collapsed the cap: %d -> %d", firstCap, st.CurrentRPMCap)
	}

	// answers again: the cap grows every interval and is lifted after the quiet period
	mode.Store(0)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = m.Resolve(context.Background(), query("again.test"))
		if st = statOf(); st.State == "healthy" && st.CurrentRPMCap == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("cap not lifted after the quiet period: %+v", statOf())
}

// The per-attempt timeout adapts to the resolver's latency within its bounds.
func TestAdaptiveTimeoutAndHedgeDelay(t *testing.T) {
	opts := Options{DefaultResolverTimeout: 2 * time.Second}
	opts.applyDefaults()
	rs := newResolverState("r", ResolverConfig{Timeout: 2 * time.Second}, nil, &opts)
	if got := rs.attemptTimeout(); got != 2*time.Second {
		t.Fatalf("unmeasured: %s", got)
	}
	if got := rs.hedgeDelay(); got != 2*time.Second {
		t.Fatalf("no loss yet: hedge at the attempt timeout, got %s", got)
	}
	rs.recentTimeouts.add(time.Now(), 1)
	if got := rs.hedgeDelay(); got != 300*time.Millisecond {
		t.Fatalf("unmeasured hedge delay: %s", got)
	}
	rs.updateLatencyEWMA(20 * time.Millisecond)
	if got := rs.attemptTimeout(); got != 300*time.Millisecond {
		t.Fatalf("fast resolver: %s", got)
	}
	if got := rs.hedgeDelay(); got != 100*time.Millisecond {
		t.Fatalf("fast resolver hedge delay: %s", got)
	}
	// a server that answers some queries at once and holds others for a
	// second: the deviation stretches the timeout past the held ones
	held := newResolverState("h", ResolverConfig{Timeout: 3 * time.Second}, nil, &opts)
	for i := 0; i < 20; i++ {
		held.updateLatencyEWMA(5 * time.Millisecond)
		held.updateLatencyEWMA(time.Second)
	}
	if got := held.attemptTimeout(); got < 1500*time.Millisecond {
		t.Fatalf("held answers would time out: %s (mean %s, dev %s)", got, held.latencyEWMA(), held.latencyVar())
	}
	rs.latencyEWMANanos.Store(int64(900 * time.Millisecond))
	rs.latencyVarNanos.Store(int64(400 * time.Millisecond))
	if got := rs.attemptTimeout(); got != 2*time.Second {
		t.Fatalf("slow resolver: %s", got)
	}
	if got := rs.hedgeDelay(); got != 1700*time.Millisecond {
		t.Fatalf("slow resolver hedge delay: %s", got)
	}
	opts.DisableAdaptiveTimeout = true
	if got := rs.attemptTimeout(); got != 2*time.Second {
		t.Fatalf("disabled: %s", got)
	}
	opts.HedgeDelay = 50 * time.Millisecond
	if got := rs.hedgeDelay(); got != 50*time.Millisecond {
		t.Fatalf("fixed hedge delay: %s", got)
	}
}

// A caller's deadline ends a hedged resolve with the deadline error.
func TestHedgedResolveHonoursDeadline(t *testing.T) {
	var mode atomic.Int32
	var served atomic.Int64
	mode.Store(1)
	addr := startBehaviourServer(t, &mode, &served)
	m := New(Options{DefaultResolverTimeout: 5 * time.Second})
	defer m.Close()
	_, _ = m.AddResolver(ResolverConfig{Protocol: ProtoUDP, Address: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := m.Resolve(ctx, query("x.test"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
