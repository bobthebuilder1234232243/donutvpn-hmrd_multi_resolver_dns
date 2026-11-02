package multidns

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// The relay is the high-throughput path a DNS tunnel uses (the local listener
// of StartLocal and PacketConn). Unlike Resolve, which runs one synchronous
// exchange per attempt, the relay keeps one long-lived socket per UDP
// resolver, rewrites query IDs to multiplex every client query over it,
// and handles answers, failures and timeouts as events:
//
//   - each query goes to the resolver with the most spare capacity
//     (LBAuto: power of two choices over in-flight count, latency and loss,
//     within each resolver's learned rate cap), or by the configured strategy;
//   - a REFUSED or SERVFAIL answer is retried at once on another resolver,
//     and teaches the resolver's rate cap;
//   - a query that finds every resolver at its cap waits for capacity (up to
//     PacingMaxWait) instead of being sent into a refusal;
//   - a resolver that lost packets lately is hedged: a query it has not
//     answered within its hedge delay is also sent to another resolver;
//   - a resolver that is down receives a copy of a live query every
//     RelayProbeInterval, and returns to service on its first answer;
//   - SpreadCount sends every query to several resolvers at once (fanout).
//
// The first answer wins; later ones are dropped. A query that every attempt
// failed is answered with the last error response, so the client can retry.

var errShortPacket = errors.New("multidns: packet too short for a DNS message")

type flight struct {
	mu          sync.Mutex
	wire        []byte // the client's query; its ID is rewritten per attempt
	origID      uint16
	deliver     func([]byte)
	created     time.Time
	deadline    time.Time
	attempts    int
	outstanding int
	tried       []*resolverState
	done        bool
	lastResp    []byte
}

func (f *flight) hasTried(rs *resolverState) bool {
	for _, t := range f.tried {
		if t == rs {
			return true
		}
	}
	return false
}

type attempt struct {
	flight     *flight
	rs         *resolverState
	id         uint16
	sent       time.Time
	timeout    time.Duration
	hedgeAfter time.Duration
	hedged     bool
	probe      bool
	// overCap: sent past the resolver's rate cap (overflow); its refusal
	// does not lower the cap
	overCap bool
}

type relay struct {
	m    *Manager
	opts *Options

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once

	waitMu  sync.Mutex
	waiting []*flight

	rr atomic.Uint64
}

func newRelay(m *Manager) *relay {
	ctx, cancel := context.WithCancel(context.Background())
	return &relay{m: m, opts: &m.opts, ctx: ctx, cancel: cancel}
}

func (r *relay) start() {
	r.once.Do(func() {
		r.wg.Add(1)
		go r.sweepLoop()
	})
}

func (r *relay) close() {
	r.cancel()
	// close the sockets first: their readers end on the read error
	for _, rs := range r.m.pool.snapshot() {
		if rs.dg != nil {
			rs.dg.close()
		}
	}
	r.wg.Wait()
}

// Submit sends a raw DNS query through the pool. deliver receives the answer
// (with the client's ID) once, from a relay goroutine; it must not block.
func (r *relay) Submit(wire []byte, deliver func([]byte)) error {
	if len(wire) < 12 {
		return errShortPacket
	}
	if r.ctx.Err() != nil {
		return net.ErrClosed
	}
	r.start()
	now := time.Now()
	f := &flight{
		wire:     append([]byte(nil), wire...),
		origID:   binary.BigEndian.Uint16(wire),
		deliver:  deliver,
		created:  now,
		deadline: now.Add(r.opts.DefaultDeadline),
	}
	r.dispatch(f, now)
	return nil
}

// dispatch sends a new query: one attempt (or SpreadCount), plus a probe copy
// to each down resolver that is due one. With no capacity left it waits.
func (r *relay) dispatch(f *flight, now time.Time) {
	rs, overCap := r.pick(f, now, false)
	if rs == nil {
		if r.opts.PacingMaxWait > 0 && r.hasEligible(f) {
			r.enqueue(f)
			return
		}
		rs, overCap = r.pick(f, now, true)
		if rs == nil {
			r.fail(f)
			return
		}
	}
	r.send(f, rs, now, false, overCap)
	for extra := r.spread() - 1; extra > 0; extra-- {
		other, _ := r.pick(f, now, false)
		if other == nil {
			break
		}
		r.send(f, other, now, false, false)
	}
	r.probeDown(f, now)
}

func (r *relay) spread() int {
	if r.opts.SpreadCount < 0 {
		return len(r.m.pool.snapshot())
	}
	if r.opts.SpreadCount < 1 {
		return 1
	}
	return r.opts.SpreadCount
}

// probeDown sends a copy of a live query to every down resolver whose last
// probe is older than RelayProbeInterval; the copy is an ordinary attempt, so
// its answer can win and returns the resolver to service.
func (r *relay) probeDown(f *flight, now time.Time) {
	for _, rs := range r.m.pool.snapshot() {
		if rs.currentState() != stateDown || f.hasTried(rs) {
			continue
		}
		last := rs.lastProbe.Load()
		if last != 0 && now.Sub(time.Unix(0, last)) < r.opts.RelayProbeInterval {
			continue
		}
		if !rs.lastProbe.CompareAndSwap(last, now.UnixNano()) {
			continue
		}
		r.send(f, rs, now, true, true)
	}
}

func (r *relay) hasEligible(f *flight) bool {
	for _, rs := range r.m.pool.snapshot() {
		if rs.currentState() != stateDown && !f.hasTried(rs) {
			return true
		}
	}
	return false
}

// pick chooses the resolver for the next attempt of f. Down resolvers and the
// ones f already tried are skipped. Unless force is set, a resolver must have
// capacity under its rate cap; force takes one anyway (and, when none is
// left, any resolver f did not try). The second result is true when the
// choice is past the resolver's cap (overflow).
func (r *relay) pick(f *flight, now time.Time, force bool) (*resolverState, bool) {
	all := r.m.pool.snapshot()
	f.mu.Lock()
	eligible := make([]*resolverState, 0, len(all))
	for _, rs := range all {
		if rs.currentState() != stateDown && !f.hasTried(rs) {
			eligible = append(eligible, rs)
		}
	}
	f.mu.Unlock()
	if len(eligible) == 0 {
		if !force {
			return nil, false
		}
		f.mu.Lock()
		for _, rs := range all {
			if !f.hasTried(rs) {
				eligible = append(eligible, rs)
			}
		}
		f.mu.Unlock()
		if len(eligible) == 0 {
			return nil, false
		}
	}

	if r.opts.LoadBalance == LBAuto {
		return r.pickAuto(eligible, now, force)
	}
	ordered := r.order(eligible)
	for _, rs := range ordered {
		if rs.bucket.tryAcquire(now) {
			return rs, false
		}
	}
	if force {
		return ordered[0], true
	}
	return nil, false
}

// pickAuto is power of two choices: among the resolvers with capacity, two
// are drawn at random and the cheaper one wins (cost: in-flight queries,
// latency and recent loss). Load spreads in proportion to what each resolver
// can take, without a central queue.
func (r *relay) pickAuto(eligible []*resolverState, now time.Time, force bool) (*resolverState, bool) {
	unmeasured := bestLatency(eligible)
	ready := make([]*resolverState, 0, len(eligible))
	for _, rs := range eligible {
		if rs.bucket.available(now) {
			ready = append(ready, rs)
		}
	}
	for len(ready) > 0 {
		choice := ready[rand.Intn(len(ready))] //nolint:gosec // load balancing, not security
		if len(ready) > 1 {
			other := ready[rand.Intn(len(ready))] //nolint:gosec
			for other == choice {
				other = ready[rand.Intn(len(ready))] //nolint:gosec
			}
			if other.cost(unmeasured) < choice.cost(unmeasured) {
				choice = other
			}
		}
		if choice.bucket.tryAcquire(now) {
			return choice, false
		}
		// lost the token to another goroutine: drop it and draw again
		for i, rs := range ready {
			if rs == choice {
				ready = append(ready[:i], ready[i+1:]...)
				break
			}
		}
	}
	if !force {
		return nil, false
	}
	// every resolver is at its cap: the one with the most of its burst
	// left, which spreads the overflow in proportion to the caps too
	best := eligible[0]
	bestLevel := best.bucket.level(now)
	for _, rs := range eligible[1:] {
		level := rs.bucket.level(now)
		if level > bestLevel || (level == bestLevel && rs.cost(unmeasured) < best.cost(unmeasured)) {
			best, bestLevel = rs, level
		}
	}
	return best, !best.bucket.tryAcquire(now)
}

// order applies the configured non-auto strategy to the eligible resolvers.
func (r *relay) order(eligible []*resolverState) []*resolverState {
	out := append([]*resolverState(nil), eligible...)
	switch r.opts.LoadBalance {
	case LBLowestLatency:
		sortByLatency(out)
	case LBWeighted:
		shuffleWeighted(out)
	default:
		rotate(out, int(r.rr.Add(1)))
	}
	return out
}

// send starts one attempt of f on rs.
func (r *relay) send(f *flight, rs *resolverState, now time.Time, probe, overCap bool) {
	a := &attempt{
		flight:     f,
		rs:         rs,
		sent:       now,
		timeout:    rs.attemptTimeout(),
		hedgeAfter: rs.hedgeDelay(),
		probe:      probe,
		overCap:    overCap || probe,
	}
	f.mu.Lock()
	f.outstanding++
	if !probe {
		f.attempts++
	}
	f.tried = append(f.tried, rs)
	wire := append([]byte(nil), f.wire...)
	f.mu.Unlock()
	rs.inflight.Add(1)
	rs.sent.Add(1)

	if rs.dg != nil {
		if err := rs.dg.send(a, wire); err != nil {
			r.complete(a, nil, err)
		}
		return
	}
	// TCP, DoT and DoH: a synchronous exchange per attempt, in its own goroutine
	go func() {
		q := new(dns.Msg)
		if err := q.Unpack(wire); err != nil {
			r.complete(a, nil, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.ctx, a.timeout)
		resp, err := rs.up.Exchange(ctx, q)
		cancel()
		if r.ctx.Err() != nil {
			return
		}
		var out []byte
		if err == nil && resp != nil {
			out, err = resp.Pack()
		}
		r.complete(a, out, err)
	}()
}

// complete records the outcome of an attempt and delivers, retries or fails
// its query.
func (r *relay) complete(a *attempt, resp []byte, err error) {
	now := time.Now()
	rs := a.rs
	rs.inflight.Add(-1)

	kind := failNone
	switch {
	case err != nil:
		kind = classify(nil, err)
		if kind == failBadResponse {
			kind = failNetwork // the relay never cancels an attempt on purpose
		}
	case len(resp) < 12:
		kind = failBadResponse
	default:
		switch int(resp[3] & 0x0F) {
		case dns.RcodeSuccess, dns.RcodeNameError:
			kind = failNone
		case dns.RcodeRefused, dns.RcodeServerFailure:
			kind = failRateLimit
		default:
			kind = failOther // FORMERR, NOTIMP, ...: the answer of the query itself
		}
	}
	rs.recordOutcome(now, kind, now.Sub(a.sent), nil, !a.overCap)

	f := a.flight
	f.mu.Lock()
	f.outstanding--
	if f.done {
		f.mu.Unlock()
		return
	}
	if kind == failNone || kind == failOther {
		f.done = true
		f.mu.Unlock()
		r.deliver(f, resp)
		return
	}
	if kind == failRateLimit {
		f.lastResp = resp
	}
	canRetry := f.attempts < r.opts.MaxAttempts && now.Before(f.deadline)
	outstanding := f.outstanding
	f.mu.Unlock()

	if canRetry {
		if next, _ := r.pick(f, now, false); next != nil {
			r.send(f, next, now, false, false)
			return
		}
		if outstanding == 0 && r.opts.PacingMaxWait > 0 && r.hasEligible(f) {
			r.enqueue(f)
			return
		}
	}
	if outstanding == 0 {
		r.fail(f)
	}
}

func (r *relay) deliver(f *flight, resp []byte) {
	out := append([]byte(nil), resp...)
	binary.BigEndian.PutUint16(out, f.origID)
	f.deliver(out)
}

// fail ends a query no attempt answered: with the last error answer if there
// was one, or SERVFAIL.
func (r *relay) fail(f *flight) {
	f.mu.Lock()
	if f.done {
		f.mu.Unlock()
		return
	}
	f.done = true
	resp := f.lastResp
	f.mu.Unlock()
	if resp == nil {
		q := new(dns.Msg)
		if err := q.Unpack(f.wire); err != nil {
			return
		}
		out, err := errResponse(q, dns.RcodeServerFailure).Pack()
		if err != nil {
			return
		}
		resp = out
	}
	r.deliver(f, resp)
}

func (r *relay) enqueue(f *flight) {
	r.waitMu.Lock()
	r.waiting = append(r.waiting, f)
	r.waitMu.Unlock()
}

// sweepLoop expires attempts, starts hedges and drains the pacing queue.
func (r *relay) sweepLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.opts.RelayTick)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-ticker.C:
			r.sweep(now)
		}
	}
}

func (r *relay) sweep(now time.Time) {
	var expired, hedges []*attempt
	for _, rs := range r.m.pool.snapshot() {
		if rs.dg == nil {
			continue
		}
		e, h := rs.dg.scan(now)
		expired = append(expired, e...)
		hedges = append(hedges, h...)
	}
	for _, a := range expired {
		r.complete(a, nil, errAttemptTimeout)
	}
	for _, a := range hedges {
		r.hedge(a.flight, now)
	}

	r.waitMu.Lock()
	waiting := r.waiting
	r.waiting = nil
	r.waitMu.Unlock()
	var still []*flight
	for _, f := range waiting {
		f.mu.Lock()
		done := f.done
		f.mu.Unlock()
		if done {
			continue
		}
		if now.After(f.deadline) {
			r.fail(f)
			continue
		}
		force := now.Sub(f.created) >= r.opts.PacingMaxWait
		rs, overCap := r.pick(f, now, force)
		if rs == nil {
			if force {
				r.fail(f)
			} else {
				still = append(still, f)
			}
			continue
		}
		r.send(f, rs, now, false, overCap)
	}
	if len(still) > 0 {
		r.waitMu.Lock()
		r.waiting = append(still, r.waiting...)
		r.waitMu.Unlock()
	}
}

// hedge sends f to one more resolver, within MaxInFlight and MaxAttempts.
func (r *relay) hedge(f *flight, now time.Time) {
	f.mu.Lock()
	ok := !f.done && f.outstanding < r.opts.MaxInFlight && f.attempts < r.opts.MaxAttempts && now.Before(f.deadline)
	f.mu.Unlock()
	if !ok {
		return
	}
	if rs, _ := r.pick(f, now, false); rs != nil {
		r.send(f, rs, now, false, false)
	}
}

var errAttemptTimeout = &timeoutErr{}

// dgram is the long-lived UDP socket of one resolver and its pending queries,
// keyed by the rewritten query ID.
type dgram struct {
	rs    *resolverState
	relay *relay

	mu      sync.Mutex
	conn    net.Conn
	nextID  uint16
	pending map[uint16]*attempt
	closed  bool
}

func newDgram(rs *resolverState, r *relay) *dgram {
	return &dgram{rs: rs, relay: r, pending: make(map[uint16]*attempt), nextID: uint16(rand.Intn(65536))} //nolint:gosec
}

// connLocked returns the socket, dialing it (through the resolver's Dialer
// when set) on first use or after a read error.
func (d *dgram) connLocked() (net.Conn, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	var conn net.Conn
	var err error
	if d.rs.cfg.Dialer != nil {
		ctx, cancel := context.WithTimeout(d.relay.ctx, d.rs.cfg.Timeout)
		conn, err = d.rs.cfg.Dialer(ctx, "udp", d.rs.cfg.Address)
		cancel()
	} else {
		conn, err = net.Dial("udp", d.rs.cfg.Address)
	}
	if err != nil {
		return nil, err
	}
	d.conn = conn
	d.relay.wg.Add(1)
	go d.readLoop(conn)
	return conn, nil
}

func (d *dgram) send(a *attempt, wire []byte) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return net.ErrClosed
	}
	conn, err := d.connLocked()
	if err != nil {
		d.mu.Unlock()
		return err
	}
	if len(d.pending) >= 65535 {
		d.mu.Unlock()
		return errors.New("multidns: too many queries in flight")
	}
	for {
		d.nextID++
		if _, used := d.pending[d.nextID]; !used {
			break
		}
	}
	a.id = d.nextID
	d.pending[a.id] = a
	d.mu.Unlock()

	binary.BigEndian.PutUint16(wire, a.id)
	if _, err := conn.Write(wire); err != nil {
		d.mu.Lock()
		delete(d.pending, a.id)
		d.mu.Unlock()
		return err
	}
	return nil
}

func (d *dgram) readLoop(conn net.Conn) {
	defer d.relay.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			d.mu.Lock()
			if d.conn == conn {
				d.conn = nil // dialed again on the next send
			}
			d.mu.Unlock()
			_ = conn.Close()
			return
		}
		if n < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(buf)
		d.mu.Lock()
		a := d.pending[id]
		if a != nil {
			delete(d.pending, id)
		}
		d.mu.Unlock()
		if a == nil {
			continue // late, duplicated or forged
		}
		d.relay.complete(a, append([]byte(nil), buf[:n]...), nil)
	}
}

// scan removes the attempts past their timeout and returns them, with the
// attempts due a hedge.
func (d *dgram) scan(now time.Time) (expired, hedges []*attempt) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, a := range d.pending {
		age := now.Sub(a.sent)
		if age >= a.timeout {
			delete(d.pending, id)
			expired = append(expired, a)
			continue
		}
		if !a.hedged && !a.probe && age >= a.hedgeAfter && a.hedgeAfter < a.timeout {
			a.hedged = true
			hedges = append(hedges, a)
		}
	}
	return expired, hedges
}

func (d *dgram) close() {
	d.mu.Lock()
	d.closed = true
	conn := d.conn
	d.conn = nil
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
