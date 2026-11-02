package multidns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type healthState int32

const (
	stateHealthy healthState = iota
	stateRateLimited
	stateDown
)

func (h healthState) String() string {
	switch h {
	case stateHealthy:
		return "healthy"
	case stateRateLimited:
		return "rate_limited"
	case stateDown:
		return "down"
	default:
		return "unknown"
	}
}

type failKind int

const (
	failNone failKind = iota
	failTimeout
	failNetwork
	failRateLimit
	failBadResponse
	failOther
)

// classify maps an Exchange result to a failKind. A non-nil response is
// inspected for Rcode regardless of err being nil so DoH/SERVFAIL paths land
// in the right bucket.
func classify(resp *dns.Msg, err error) failKind {
	if err != nil {
		// Caller-side cancellation is not the resolver's fault — never
		// charge consecutiveFails for it, otherwise N caller cancels would
		// trip a healthy resolver into the down state.
		if errors.Is(err, context.Canceled) {
			return failBadResponse
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return failTimeout
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return failTimeout
		}
		// HTTP 429 from the DoH transport surfaces as a wrapped error; we
		// flag it via a sentinel string rather than a typed error to avoid
		// leaking the internal type.
		if strings.Contains(err.Error(), "doh: rate limited") {
			return failRateLimit
		}
		if strings.Contains(err.Error(), "doh: server error") {
			return failRateLimit
		}
		return failNetwork
	}
	if resp == nil {
		return failBadResponse
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return failNone
	case dns.RcodeRefused, dns.RcodeServerFailure:
		return failRateLimit
	case dns.RcodeFormatError, dns.RcodeNotImplemented:
		return failBadResponse
	default:
		return failOther
	}
}

// resolverState carries everything we know about a single upstream and its
// runtime health.
type resolverState struct {
	id   string
	cfg  ResolverConfig
	up   upstream
	opts *Options

	state atomic.Int32

	validCount       atomic.Int64
	invalidCount     atomic.Int64
	timeoutCount     atomic.Int64
	rateLimitedCount atomic.Int64

	consecutiveFails atomic.Int64

	// relay: the long-lived socket (UDP only), queries in flight, queries
	// sent, and the last probe sent while down
	dg        *dgram
	inflight  atomic.Int64
	sent      atomic.Int64
	lastProbe atomic.Int64

	recentReqs     slidingCounter
	recentOK       slidingCounter
	recentRL       slidingCounter
	recentTimeouts slidingCounter

	bucket *tokenBucket

	// latencyEWMANanos is the EWMA of successful Exchange latencies, in
	// nanoseconds. Stored atomically so candidate selection (sort) can read
	// it without holding mu.
	latencyEWMANanos atomic.Int64
	// latencyVarNanos is the smoothed mean deviation of the latency, as in
	// TCP's RTTVAR: it makes the timeout grow for a server that holds some
	// answers (a DNS tunnel server keeps polls until it has data).
	latencyVarNanos atomic.Int64

	mu           sync.Mutex
	failingQuery *dns.Msg
	lastValid    time.Time
	lastFail     time.Time

	// rrAdditiveAt is the next wall-clock at which the cap grows when no
	// refusal has been seen; lastDecrease and lastRateLimit bound how often
	// the cap drops and when it is lifted.
	rrAdditiveAt  time.Time
	lastDecrease  time.Time
	lastRateLimit time.Time

	probeCancel context.CancelFunc
}

func newResolverState(id string, cfg ResolverConfig, up upstream, opts *Options) *resolverState {
	rs := &resolverState{
		id:     id,
		cfg:    cfg,
		up:     up,
		opts:   opts,
		bucket: newTokenBucket(cfg.InitialRPM),
	}
	rs.state.Store(int32(stateHealthy))
	return rs
}

func (rs *resolverState) currentState() healthState {
	return healthState(rs.state.Load())
}

func (rs *resolverState) setState(s healthState) {
	rs.state.Store(int32(s))
}

// record updates counters, sliding windows, and state transitions for one
// completed (or failed) Exchange attempt.
func (rs *resolverState) record(now time.Time, kind failKind, latency time.Duration, q *dns.Msg) {
	rs.recordOutcome(now, kind, latency, q, true)
}

// recordOutcome is record with teach: false for a query the relay sent past
// the resolver's cap on purpose. Its refusal or loss is counted but does not
// lower the cap, which would otherwise ratchet down under overflow.
func (rs *resolverState) recordOutcome(now time.Time, kind failKind, latency time.Duration, q *dns.Msg, teach bool) {
	rs.recentReqs.add(now, 1)

	switch kind {
	case failNone:
		rs.validCount.Add(1)
		rs.recentOK.add(now, 1)
		rs.consecutiveFails.Store(0)
		rs.updateLatencyEWMA(latency)
		rs.mu.Lock()
		rs.lastValid = now
		rs.failingQuery = nil
		rs.mu.Unlock()
		rs.maybeAdditiveIncrease(now)
		if rs.currentState() != stateHealthy && rs.bucket.cap() == 0 {
			rs.setState(stateHealthy)
		}

	case failBadResponse:
		// Don't penalise the resolver — likely client-side issue.
		return

	case failTimeout:
		rs.timeoutCount.Add(1)
		rs.recentTimeouts.add(now, 1)
		rs.invalidCount.Add(1)
		rs.consecutiveFails.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		// A resolver that drops queries while it still answers others is
		// rate limiting silently: cap it like one that refuses.
		if teach && rs.recentOK.sumLast(now, 2) > 0 && rs.recentTimeouts.sumLast(now, 2) >= 3 {
			rs.applyRateLimitDecrease(now)
		}
		rs.maybeMarkDown(q)

	case failNetwork:
		rs.invalidCount.Add(1)
		rs.consecutiveFails.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		rs.maybeMarkDown(q)

	case failRateLimit:
		rs.invalidCount.Add(1)
		rs.rateLimitedCount.Add(1)
		rs.recentRL.add(now, 1)
		rs.consecutiveFails.Store(0)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
		if teach {
			rs.applyRateLimitDecrease(now)
		} else {
			rs.mu.Lock()
			rs.lastRateLimit = now
			rs.mu.Unlock()
		}

	default:
		rs.invalidCount.Add(1)
		rs.mu.Lock()
		rs.lastFail = now
		rs.mu.Unlock()
	}
}

func (rs *resolverState) maybeMarkDown(q *dns.Msg) {
	threshold := int64(rs.opts.DownAfterFailures)
	if threshold <= 0 {
		threshold = 8
	}
	if rs.consecutiveFails.Load() < threshold {
		return
	}
	// A resolver that still answered within the last seconds is dropping
	// what exceeds its rate, not dead: it is capped (see record), not taken
	// out of service.
	if rs.recentOK.sumLast(time.Now(), 3) > 0 {
		return
	}
	if rs.currentState() == stateDown {
		return
	}
	rs.mu.Lock()
	if q != nil {
		rs.failingQuery = q.Copy()
	}
	rs.mu.Unlock()
	rs.setState(stateDown)
}

// applyRateLimitDecrease drops the cap to a share of what the resolver has
// really been answering lately (not half of what was sent, which under a
// tunnel is mostly retransmissions). A burst of refusals from queries that
// were already in flight counts once per recovery interval.
func (rs *resolverState) applyRateLimitDecrease(now time.Time) {
	rs.mu.Lock()
	if !rs.lastDecrease.IsZero() && now.Sub(rs.lastDecrease) < rs.opts.RateLimitRecoveryInterval {
		rs.lastRateLimit = now
		rs.mu.Unlock()
		rs.setState(stateRateLimited)
		return
	}
	rs.lastDecrease = now
	rs.lastRateLimit = now
	rs.rrAdditiveAt = now.Add(rs.opts.RateLimitRecoveryInterval)
	rs.mu.Unlock()

	windowSec := int(rs.opts.RateLimitWindow / time.Second)
	if windowSec < 1 {
		windowSec = 1
	}
	okPerMin := float64(rs.recentOK.sumLast(now, windowSec)) / float64(windowSec) * 60
	newCap := int(okPerMin * rs.opts.RateLimitDecreaseFactor)
	if cap := rs.bucket.cap(); cap > 0 && okPerMin >= float64(cap)/2 {
		// refused near the cap: step down from the cap. (The success rate
		// under-reads a bursty client, and would drag the cap down with it.)
		newCap = int(float64(cap) * rs.opts.RateLimitDecreaseFactor)
	}
	if newCap < rs.opts.RateLimitFloorRPM {
		newCap = rs.opts.RateLimitFloorRPM
	}
	rs.bucket.setCap(newCap)
	rs.setState(stateRateLimited)
}

// maybeAdditiveIncrease grows the cap every recovery interval without a
// refusal, by a share of itself (fast, like a congestion window), and lifts
// it after RateLimitUncapAfter quiet, or once it passes RateLimitUncapRPM.
func (rs *resolverState) maybeAdditiveIncrease(now time.Time) {
	cap := rs.bucket.cap()
	if cap == 0 {
		return
	}
	rs.mu.Lock()
	due := !rs.rrAdditiveAt.IsZero() && now.After(rs.rrAdditiveAt)
	if due {
		rs.rrAdditiveAt = now.Add(rs.opts.RateLimitRecoveryInterval)
	}
	quietFor := now.Sub(rs.lastRateLimit)
	rs.mu.Unlock()
	if !due {
		return
	}
	intervalSec := int((rs.opts.RateLimitRecoveryInterval + time.Second - 1) / time.Second)
	if rs.recentRL.sumLast(now, intervalSec) > 0 {
		return
	}
	step := int(float64(cap) * rs.opts.RateLimitIncreaseFactor)
	if step < rs.opts.RateLimitAdditive {
		step = rs.opts.RateLimitAdditive
	}
	if step < 1 {
		step = 1
	}
	newCap := cap + step
	// lift the cap only when it is not what keeps the resolver from refusing:
	// while the cap holds queries back, it grows step by step instead
	notLimiting := !rs.bucket.deniedSince(now.Add(-rs.opts.RateLimitUncapAfter))
	if (rs.opts.RateLimitUncapRPM > 0 && newCap >= rs.opts.RateLimitUncapRPM) || (quietFor >= rs.opts.RateLimitUncapAfter && notLimiting) {
		rs.bucket.setCap(0)
		rs.setState(stateHealthy)
		return
	}
	rs.bucket.setCap(newCap)
}

// lossRate is the share of this resolver's recent queries that timed out.
func (rs *resolverState) lossRate(now time.Time) float64 {
	sent := rs.recentReqs.sumLast(now, 10)
	if sent <= 0 {
		return 0
	}
	return float64(rs.recentTimeouts.sumLast(now, 10)) / float64(sent)
}

// cost ranks resolvers for LBAuto: queries in flight, latency and loss.
// unmeasured is the latency assumed for a resolver with no answer yet; the
// callers pass the best latency among its peers, so a new resolver is
// sampled as soon as it is not busier than they are.
func (rs *resolverState) cost(unmeasured time.Duration) float64 {
	latency := rs.latencyEWMA()
	if latency <= 0 {
		latency = unmeasured
	}
	if latency <= 0 {
		latency = time.Millisecond
	}
	return float64(rs.inflight.Load()+1) * float64(latency) * (1 + 4*rs.lossRate(time.Now()))
}

// bestLatency is the lowest measured latency among rs, 0 when none is.
func bestLatency(rs []*resolverState) time.Duration {
	var best time.Duration
	for _, r := range rs {
		if l := r.latencyEWMA(); l > 0 && (best == 0 || l < best) {
			best = l
		}
	}
	return best
}

// attemptTimeout is the per-attempt cap for this resolver: its configured
// timeout, or with adaptive timeouts its mean latency plus four deviations
// (TCP's RTO) within [AdaptiveTimeoutMin, timeout].
func (rs *resolverState) attemptTimeout() time.Duration {
	timeout := rs.cfg.Timeout
	if rs.opts.DisableAdaptiveTimeout || timeout <= 0 {
		return timeout
	}
	ewma := rs.latencyEWMA()
	if ewma <= 0 {
		return timeout
	}
	// TCP's retransmission timeout: the mean plus four deviations
	adaptive := ewma + 4*rs.latencyVar()
	if adaptive < rs.opts.AdaptiveTimeoutMin {
		adaptive = rs.opts.AdaptiveTimeoutMin
	}
	if adaptive > timeout {
		adaptive = timeout
	}
	return adaptive
}

// hedgeDelay is how long a query waits on this resolver before it is also
// sent to the next candidate. A fixed HedgeDelay always applies. The adaptive
// delay (HedgeDelay 0) hedges only a resolver that has lost packets within
// HedgeLossWindow: its mean latency plus two deviations, within [HedgeMinDelay, attempt
// timeout]. A resolver with no recent loss is given its whole attempt
// timeout, because a second copy of every query would spend the quota of a
// rate-limited resolver twice for nothing.
func (rs *resolverState) hedgeDelay() time.Duration {
	if rs.opts.HedgeDelay > 0 {
		return rs.opts.HedgeDelay
	}
	lossWindow := int((rs.opts.HedgeLossWindow + time.Second - 1) / time.Second)
	if rs.recentTimeouts.sumLast(time.Now(), lossWindow) == 0 {
		return rs.attemptTimeout()
	}
	delay := rs.latencyEWMA() + 2*rs.latencyVar()
	if delay <= 0 {
		delay = 3 * rs.opts.HedgeMinDelay
	}
	if delay < rs.opts.HedgeMinDelay {
		delay = rs.opts.HedgeMinDelay
	}
	if timeout := rs.attemptTimeout(); timeout > 0 && delay > timeout {
		delay = timeout
	}
	return delay
}

func (rs *resolverState) updateLatencyEWMA(latency time.Duration) {
	cur := rs.latencyEWMANanos.Load()
	sample := int64(latency)
	if cur == 0 {
		rs.latencyEWMANanos.Store(sample)
		rs.latencyVarNanos.Store(sample / 2)
		return
	}
	dev := sample - cur
	if dev < 0 {
		dev = -dev
	}
	rs.latencyVarNanos.Store((rs.latencyVarNanos.Load()*3 + dev) / 4)
	rs.latencyEWMANanos.Store((cur*7 + sample) / 8)
}

func (rs *resolverState) latencyVar() time.Duration {
	return time.Duration(rs.latencyVarNanos.Load())
}

func (rs *resolverState) latencyEWMA() time.Duration {
	return time.Duration(rs.latencyEWMANanos.Load())
}

func (rs *resolverState) snapshot() ResolverStat {
	rs.mu.Lock()
	lastValid := rs.lastValid
	lastFail := rs.lastFail
	rs.mu.Unlock()
	return ResolverStat{
		ID:            rs.id,
		Name:          rs.cfg.Name,
		State:         rs.currentState().String(),
		ValidCount:    rs.validCount.Load(),
		InvalidCount:  rs.invalidCount.Load(),
		TimeoutCount:  rs.timeoutCount.Load(),
		RateLimited:   rs.rateLimitedCount.Load(),
		CurrentRPMCap: rs.bucket.cap(),
		RecentRPM:     int(rs.recentReqs.sum(time.Now())),
		InFlight:      rs.inflight.Load(),
		Sent:          rs.sent.Load(),
		LossRate:      rs.lossRate(time.Now()),
		LatencyEWMA:   rs.latencyEWMA(),
		LastValid:     lastValid,
		LastFail:      lastFail,
	}
}

func (rs *resolverState) info() ResolverInfo {
	return ResolverInfo{
		ID:       rs.id,
		Name:     rs.cfg.Name,
		Protocol: rs.cfg.Protocol,
		Address:  rs.cfg.Address,
		Weight:   rs.cfg.Weight,
	}
}
