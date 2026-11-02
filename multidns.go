// Package multidns implements an intelligent multi-resolver DNS proxy.
//
// A Manager owns a set of upstream resolvers (UDP, TCP, DoT, DoH), accepts
// dns.Msg queries via Resolve, and:
//
//   - load-balances across healthy upstreams,
//   - retries on a different upstream when one fails or times out, while
//     respecting the caller's overall deadline,
//   - classifies failures and adaptively throttles upstreams that signal
//     rate-limiting (REFUSED / SERVFAIL / HTTP 429),
//   - probes downed upstreams in the background until they recover, using
//     the very query that triggered the outage,
//   - supports dynamic AddResolver / RemoveResolver at runtime,
//   - lets each resolver carry a custom DialFunc so DNS traffic can be
//     routed through a tunnel (e.g. hiddify-sing-box outbound).
//
// An optional built-in Server exposes the manager as a UDP+TCP DNS listener.
package multidns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Manager is the top-level multi-resolver orchestrator.
type Manager struct {
	opts Options
	pool *pool

	mu     sync.Mutex
	closed bool
	idSeq  atomic.Uint64

	probeCtx    context.Context
	probeCancel context.CancelFunc
	probeWG     sync.WaitGroup

	// local is non-nil when this Manager was built via StartLocal. Close
	// then also tears down the bundled UDP+TCP listener.
	local *localListener

	// relay is the asynchronous path of StartLocal and PacketConn.
	relay *relay
}

// New constructs a Manager. The returned manager is ready for AddResolver
// calls; queries to Resolve will fail with ErrNoResolvers until at least one
// resolver is registered.
func New(opts Options) *Manager {
	opts.applyDefaults()
	probeCtx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		opts:        opts,
		probeCtx:    probeCtx,
		probeCancel: cancel,
	}
	m.pool = newPool(&m.opts)
	m.relay = newRelay(m)
	return m
}

// Submit sends a raw DNS query (wire format) through the pool's relay and
// returns at once. deliver is called once with the answer, carrying the
// query's ID: the first resolver's answer, or the last error answer when
// every attempt failed. deliver runs on a relay goroutine and must not block.
// This is the high-throughput path for DNS tunnels; Resolve is the
// synchronous one.
func (m *Manager) Submit(wire []byte, deliver func([]byte)) error {
	return m.relay.Submit(wire, deliver)
}

// AddResolver registers a new upstream and starts its prober. The returned id
// can later be passed to RemoveResolver.
func (m *Manager) AddResolver(cfg ResolverConfig) (string, error) {
	if cfg.Name == "" {
		cfg.Name = string(cfg.Protocol) + "://" + cfg.Address
	}
	// Normalize the per-attempt timeout *before* we hand cfg to newUpstream
	// and resolverState. Leaving cfg.Timeout==0 stranded on resolverState
	// would defeat failover: pool.attempt's capContext would inherit only
	// the overall ctx deadline, letting one hung resolver burn the whole
	// budget.
	if cfg.Timeout <= 0 {
		cfg.Timeout = m.opts.DefaultResolverTimeout
	}
	// Build the upstream before grabbing the lock so we don't block Close
	// behind any per-protocol initialization (today this is non-blocking, but
	// the contract is friendlier this way).
	up, err := newUpstream(cfg)
	if err != nil {
		return "", err
	}

	// Hold m.mu for the entire register-and-spawn sequence so that probeWG.Add
	// cannot race with Close's probeWG.Wait. Close also takes m.mu before it
	// flips closed=true, so once we've passed the check inside the lock the
	// goroutine spawn is safe.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = up.Close()
		return "", errors.New("multidns: manager closed")
	}
	id := fmt.Sprintf("r-%d", m.idSeq.Add(1))
	rs := newResolverState(id, cfg, up, &m.opts)
	if cfg.Protocol == ProtoUDP {
		rs.dg = newDgram(rs, m.relay)
	}
	m.pool.add(rs)
	m.startProbe(rs)
	m.mu.Unlock()

	m.opts.Logger.Infof("multidns: added resolver %s (%s %s)", id, cfg.Protocol, cfg.Address)
	return id, nil
}

// RemoveResolver tears down a resolver registered earlier by AddResolver.
// In-flight queries already dispatched to that resolver are allowed to
// complete (they hit upstream.Close after returning).
func (m *Manager) RemoveResolver(id string) error {
	rs, ok := m.pool.remove(id)
	if !ok {
		return fmt.Errorf("multidns: resolver %q not found", id)
	}
	rs.mu.Lock()
	cancel := rs.probeCancel
	rs.probeCancel = nil
	rs.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if rs.dg != nil {
		rs.dg.close()
	}
	if err := rs.up.Close(); err != nil {
		m.opts.Logger.Warnf("multidns: closing resolver %s: %v", id, err)
	}
	m.opts.Logger.Infof("multidns: removed resolver %s", id)
	return nil
}

// Resolvers returns a static description of every registered resolver.
func (m *Manager) Resolvers() []ResolverInfo {
	rs := m.pool.snapshot()
	out := make([]ResolverInfo, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.info())
	}
	return out
}

// Stats returns a runtime snapshot for every registered resolver.
func (m *Manager) Stats() []ResolverStat {
	rs := m.pool.snapshot()
	out := make([]ResolverStat, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.snapshot())
	}
	return out
}

// Resolve dispatches q to the pool. If ctx has no deadline, opts.DefaultDeadline
// is applied. The selected resolver is retried on the next candidate when it
// fails, until the deadline expires or every candidate has been tried.
func (m *Manager) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if q == nil {
		return nil, errors.New("multidns: nil query")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.opts.DefaultDeadline)
		defer cancel()
	}
	return m.pool.resolve(ctx, q)
}

// Close stops all probers, closes every upstream, and shuts the bundled
// local listener if one was started via StartLocal. Subsequent calls are
// no-ops.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	local := m.local
	m.mu.Unlock()

	var firstErr error
	if local != nil {
		if err := local.shutdown(); err != nil {
			firstErr = err
		}
	}

	m.probeCancel()
	m.probeWG.Wait()
	m.relay.close()

	for _, r := range m.pool.snapshot() {
		_ = r.up.Close()
	}
	return firstErr
}
