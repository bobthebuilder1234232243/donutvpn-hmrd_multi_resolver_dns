package multidns

import (
	"context"
	"errors"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ErrAllResolversFailed is returned when every candidate resolver was tried
// (or skipped) without producing a usable response inside the deadline.
var ErrAllResolversFailed = errors.New("multidns: all resolvers failed")

// ErrNoResolvers is returned when Resolve is called but no resolvers are
// registered.
var ErrNoResolvers = errors.New("multidns: no resolvers registered")

// errThrottled is an internal sentinel signalling the bucket rejected the
// attempt; the pool uses it to decide whether to fall back to forcing a
// throttled candidate.
var errThrottled = errors.New("multidns: throttled")

type pool struct {
	mu        sync.RWMutex
	resolvers []*resolverState
	rrIndex   atomic.Uint64
	opts      *Options
}

func newPool(opts *Options) *pool {
	return &pool{opts: opts}
}

func (p *pool) add(rs *resolverState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	updated := make([]*resolverState, 0, len(p.resolvers)+1)
	updated = append(updated, p.resolvers...)
	updated = append(updated, rs)
	p.resolvers = updated
}

func (p *pool) remove(id string) (*resolverState, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, r := range p.resolvers {
		if r.id == id {
			updated := make([]*resolverState, 0, len(p.resolvers)-1)
			updated = append(updated, p.resolvers[:i]...)
			updated = append(updated, p.resolvers[i+1:]...)
			p.resolvers = updated
			return r, true
		}
	}
	return nil, false
}

func (p *pool) snapshot() []*resolverState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*resolverState, len(p.resolvers))
	copy(out, p.resolvers)
	return out
}

// candidates orders resolvers for one query: healthy first, then rate_limited,
// skipping anything currently down. Within healthy/rate_limited the order
// depends on LBStrategy.
func (p *pool) candidates() []*resolverState {
	resolvers := p.snapshot()
	if len(resolvers) == 0 {
		return nil
	}

	var healthy, limited []*resolverState
	for _, r := range resolvers {
		switch r.currentState() {
		case stateHealthy:
			healthy = append(healthy, r)
		case stateRateLimited:
			limited = append(limited, r)
		}
	}

	switch p.opts.LoadBalance {
	case LBAuto:
		sortByCost(healthy)
		sortByCost(limited)
	case LBLowestLatency:
		sortByLatency(healthy)
		sortByLatency(limited)
	case LBWeighted:
		// Real weighted selection: each candidate is picked with
		// probability proportional to its Weight. Weight == 0 means the
		// resolver is a fallback (only used if the weighted draw misses).
		// The remaining candidates fan out behind the chosen primary in a
		// random order so failover is also weighted.
		shuffleWeighted(healthy)
		shuffleWeighted(limited)
	default: // round-robin
		rotate(healthy, int(p.rrIndex.Add(1)))
	}

	out := make([]*resolverState, 0, len(healthy)+len(limited))
	out = append(out, healthy...)
	out = append(out, limited...)
	return out
}

// sortByCost orders by LBAuto's cost, equal costs in random order.
func sortByCost(rs []*resolverState) {
	rand.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
	unmeasured := bestLatency(rs)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].cost(unmeasured) < rs[j].cost(unmeasured) })
}

func sortByLatency(rs []*resolverState) {
	sort.SliceStable(rs, func(i, j int) bool {
		li, lj := rs[i].latencyEWMA(), rs[j].latencyEWMA()
		// Unmeasured resolvers (EWMA == 0) sort *first* so they are
		// definitely sampled at least once. Otherwise, since Resolve
		// returns on the first success, an established slow resolver
		// would forever shadow a freshly-added fast one.
		switch {
		case li == 0 && lj == 0:
			return false
		case li == 0:
			return true
		case lj == 0:
			return false
		}
		return li < lj
	})
}

// shuffleWeighted reorders rs in place such that the first element is chosen
// with probability proportional to Weight (Weight 0 ⇒ pure fallback, only
// reached if every weighted candidate fails). After picking the first slot,
// the same procedure is applied to the remainder, so failover order is also
// weighted. This replaces the previous sort+rotate which gave every resolver
// the first attempt equally often regardless of weight.
func shuffleWeighted(rs []*resolverState) {
	for i := 0; i < len(rs); i++ {
		// Sum weights for the unselected suffix.
		var total int
		for j := i; j < len(rs); j++ {
			w := rs[j].cfg.Weight
			if w < 0 {
				w = 0
			}
			total += w
		}
		// If every remaining candidate has weight 0, leave their order
		// alone (they're all equivalent fallbacks).
		if total == 0 {
			return
		}
		pick := rand.Intn(total) //nolint:gosec // not security-sensitive
		for j := i; j < len(rs); j++ {
			w := rs[j].cfg.Weight
			if w < 0 {
				w = 0
			}
			if pick < w {
				rs[i], rs[j] = rs[j], rs[i]
				break
			}
			pick -= w
		}
	}
}

func rotate(rs []*resolverState, by int) {
	if len(rs) <= 1 {
		return
	}
	by = by % len(rs)
	if by < 0 {
		by += len(rs)
	}
	tmp := make([]*resolverState, len(rs))
	copy(tmp, rs)
	copy(rs, tmp[by:])
	copy(rs[len(rs)-by:], tmp[:by])
}

// resolve runs the deadline-aware retry across candidates, with hedging: a
// candidate that has not answered within its hedge delay is kept running
// while the next one is tried, up to MaxInFlight at once; the first answer
// wins and the other attempts are cancelled without being charged. A
// resolver that drops packets therefore costs a fraction of its timeout, not
// all of it.
func (p *pool) resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	candidates := p.candidates()
	if len(candidates) == 0 {
		// If everything is down, still fall back to the full set so a probe
		// path or a transient classification doesn't strand the caller.
		all := p.snapshot()
		if len(all) == 0 {
			return nil, ErrNoResolvers
		}
		candidates = all
	}

	hedgeCtx, cancelHedges := context.WithCancel(ctx)
	defer cancelHedges()

	type result struct {
		resp *dns.Msg
		err  error
		ok   bool
	}
	results := make(chan result, len(candidates)+1)
	maxInFlight := p.opts.MaxInFlight
	if p.opts.DisableHedging || maxInFlight < 1 {
		maxInFlight = 1
	}

	var lastErr error
	everSent := false
	inFlight := 0
	next := 0
	var last *resolverState
	// launch starts the next candidate the bucket admits; false when none is left.
	launch := func() bool {
		for next < len(candidates) {
			c := candidates[next]
			next++
			if !c.bucket.tryAcquire(time.Now()) {
				lastErr = errThrottled
				continue
			}
			everSent = true
			inFlight++
			last = c
			go func() {
				resp, err, ok := p.attempt(hedgeCtx, c, q)
				results <- result{resp: resp, err: err, ok: ok}
			}()
			return true
		}
		return false
	}

	launch()
	for inFlight > 0 {
		var hedge <-chan time.Time
		var timer *time.Timer
		if inFlight < maxInFlight && next < len(candidates) && last != nil {
			timer = time.NewTimer(last.hedgeDelay())
			hedge = timer.C
		}
		select {
		case r := <-results:
			inFlight--
			if r.ok {
				if timer != nil {
					timer.Stop()
				}
				return r.resp, nil
			}
			if r.err != nil && !errors.Is(r.err, context.Canceled) {
				lastErr = r.err
			}
			launch()
		case <-hedge:
			launch()
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, errors.Join(ErrAllResolversFailed, ctx.Err())
		}
		if timer != nil {
			timer.Stop()
		}
	}

	// If every candidate was throttled, force *one* through (ignore the
	// bucket) so callers aren't stranded by aggressive AIMD. Crucially we
	// only force the first candidate — looping over all of them here would
	// amplify traffic by N× under heavy rate-limiting and defeat the AIMD
	// design entirely.
	if !everSent && len(candidates) > 0 && ctx.Err() == nil {
		resp, err, ok := p.attempt(ctx, candidates[0], q)
		if ok {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = ErrAllResolversFailed
	}
	return nil, errors.Join(ErrAllResolversFailed, lastErr)
}

func (p *pool) attempt(ctx context.Context, c *resolverState, q *dns.Msg) (*dns.Msg, error, bool) {
	attemptCtx, cancel := capContext(ctx, c.attemptTimeout())
	start := time.Now()
	c.inflight.Add(1)
	c.sent.Add(1)
	resp, err := c.up.Exchange(attemptCtx, q)
	c.inflight.Add(-1)
	cancel()
	latency := time.Since(start)

	// If the caller's context was *cancelled* (not deadlined) we must not
	// charge this attempt against the resolver. Many transports surface
	// caller cancellation as an i/o timeout, which classify would otherwise
	// route to failTimeout and eventually drive a healthy resolver to the
	// down state. Distinguishing here, where we still have access to the
	// parent ctx, is the only reliable place. A hedged attempt that lost to
	// another resolver's answer ends the same way.
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, ctx.Err(), false
	}

	kind := classify(resp, err)
	c.record(time.Now(), kind, latency, q)
	if kind == failNone {
		return resp, nil, true
	}
	if err == nil && resp != nil {
		err = errFromRcode(resp.Rcode)
	}
	return nil, err, false
}

// capContext returns a context whose deadline is the earlier of the parent's
// deadline and now+cap. cap <= 0 means no per-attempt cap.
func capContext(parent context.Context, perAttempt time.Duration) (context.Context, context.CancelFunc) {
	if perAttempt <= 0 {
		return context.WithCancel(parent)
	}
	deadline := time.Now().Add(perAttempt)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return context.WithDeadline(parent, deadline)
}

func errFromRcode(rcode int) error {
	return &rcodeErr{rcode: rcode}
}

type rcodeErr struct{ rcode int }

func (e *rcodeErr) Error() string { return "multidns: upstream rcode " + dns.RcodeToString[e.rcode] }
