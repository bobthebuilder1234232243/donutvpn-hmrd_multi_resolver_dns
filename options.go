package multidns

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Protocol identifies the wire transport used to talk to an upstream resolver.
type Protocol string

const (
	ProtoUDP Protocol = "udp"
	ProtoTCP Protocol = "tcp"
	ProtoDoT Protocol = "dot"
	ProtoDoH Protocol = "doh"
)

// LBStrategy controls candidate ordering when multiple resolvers are healthy.
type LBStrategy int

const (
	LBRoundRobin LBStrategy = iota
	LBWeighted
	LBLowestLatency
	// LBAuto sends each query to the resolver with the most spare capacity:
	// power of two choices over in-flight queries, latency and recent loss,
	// within each resolver's learned rate cap. It needs no tuning and is the
	// best choice for DNS tunnels.
	LBAuto
)

// DialFunc is the optional custom dialer hook. When set on a ResolverConfig
// it is used for UDP/TCP/DoT connections and as the http.Transport DialContext
// for DoH, so an embedder (e.g. hiddify-sing-box) can route DNS through a tunnel.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ResolverConfig describes a single upstream resolver.
type ResolverConfig struct {
	Name       string
	Protocol   Protocol
	Address    string
	Timeout    time.Duration
	TLSConfig  *tls.Config
	Dialer     DialFunc
	Weight     int
	InitialRPM int
}

// Options configures a Manager.
type Options struct {
	DefaultDeadline   time.Duration
	LoadBalance       LBStrategy
	ProbeInterval     time.Duration
	DownAfterFailures int
	RateLimitFloorRPM int
	RateLimitUncapRPM int
	RateLimitAdditive int
	// DefaultResolverTimeout is the per-attempt cap applied to a resolver
	// when its ResolverConfig.Timeout is unset. Defaults to 2s. This exists
	// so a single hung upstream cannot consume the entire DefaultDeadline
	// before failover kicks in. The effective per-attempt timeout adapts
	// below this cap to the resolver's measured latency (see AdaptiveTimeout).
	DefaultResolverTimeout time.Duration

	// Rate limiting is automatic: it is driven by what each resolver really
	// delivers, so a DNS tunnel sending hundreds of queries per second and an
	// ordinary stub resolver both get the right cap without tuning.
	//
	// RateLimitWindow is how far back the success rate is measured when a
	// resolver refuses, or drops packets while it answers others (default
	// 3s). RateLimitDecreaseFactor is the share of that rate the cap drops to
	// (default 0.9). RateLimitIncreaseFactor is the share added every
	// RateLimitRecoveryInterval (default 1s) while no refusal arrives
	// (default 0.1, at least RateLimitAdditive per step), so the cap keeps
	// probing just above what the resolver takes. RateLimitUncapAfter lifts
	// the cap once no refusal has been seen and the cap has not held queries
	// back for this long (default 15s); RateLimitUncapRPM lifts it earlier
	// when the cap grows past that rate.
	RateLimitWindow           time.Duration
	RateLimitDecreaseFactor   float64
	RateLimitIncreaseFactor   float64
	RateLimitRecoveryInterval time.Duration
	RateLimitUncapAfter       time.Duration

	// Hedging sends a query to the next candidate when the first has not
	// answered within a delay. HedgeDelay 0 means adaptive: a resolver that
	// lost packets within HedgeLossWindow (default 10s) is hedged after its
	// mean latency plus two deviations, at least HedgeMinDelay (default
	// 100ms) and at most
	// the per-attempt timeout; a resolver with no recent loss gets its whole
	// attempt timeout, so no quota is spent on second copies while it works.
	// The first answer wins and the other attempts are cancelled without
	// being charged. MaxInFlight bounds the attempts of one query that run
	// at once (default 2). DisableHedging restores strictly sequential
	// attempts.
	HedgeDelay      time.Duration
	HedgeMinDelay   time.Duration
	HedgeLossWindow time.Duration
	MaxInFlight     int
	DisableHedging  bool

	// AdaptiveTimeout, on by default, caps each attempt at the resolver's
	// mean latency plus four mean deviations, like TCP's retransmission
	// timeout (at least AdaptiveTimeoutMin, default 300ms, never above the
	// resolver's Timeout): a lossy resolver is given up quickly, and a server
	// that holds some answers (a DNS tunnel's polls) gets the time it needs.
	// DisableAdaptiveTimeout turns it off.
	AdaptiveTimeoutMin     time.Duration
	DisableAdaptiveTimeout bool

	// The relay (StartLocal and PacketConn), the high-throughput path a DNS
	// tunnel uses. MaxAttempts bounds the resolvers one query is sent to,
	// retries and hedges included (default 3). SpreadCount sends every query
	// to that many resolvers at once, the first answer winning (default 1;
	// -1 sends to all, "fanout"). PacingMaxWait, when set, makes a query that
	// finds every resolver at its rate cap wait that long for capacity before
	// it is sent anyway; by default (0) it is sent at once to the resolver
	// with the most capacity left relative to its cap, because a DNS tunnel
	// loses more from the extra delay than from a refused query, which it
	// retransmits. RelayProbeInterval is how often a down resolver gets a copy of
	// a live query (default 1s). RelayTick is the timer of timeouts, hedges
	// and pacing (default 10ms).
	MaxAttempts        int
	SpreadCount        int
	PacingMaxWait      time.Duration
	RelayProbeInterval time.Duration
	RelayTick          time.Duration

	Logger Logger
}

// Logger is the minimal logging surface; defaults to a no-op. Embedders
// (e.g. sing-box) inject their own.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

func (o *Options) applyDefaults() {
	if o.DefaultDeadline <= 0 {
		o.DefaultDeadline = 5 * time.Second
	}
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = 5 * time.Second
	}
	if o.DownAfterFailures <= 0 {
		o.DownAfterFailures = 8
	}
	if o.RateLimitFloorRPM <= 0 {
		o.RateLimitFloorRPM = 6
	}
	if o.RateLimitUncapRPM <= 0 {
		// far above any one resolver: the cap is lifted by RateLimitUncapAfter,
		// once it no longer holds queries back. 600 lifted every cap above
		// 10 queries a second as soon as it grew.
		o.RateLimitUncapRPM = 60000
	}
	if o.RateLimitAdditive <= 0 {
		o.RateLimitAdditive = 5
	}
	if o.DefaultResolverTimeout <= 0 {
		o.DefaultResolverTimeout = 2 * time.Second
	}
	if o.RateLimitWindow <= 0 {
		o.RateLimitWindow = 3 * time.Second
	}
	if o.RateLimitDecreaseFactor <= 0 || o.RateLimitDecreaseFactor >= 1 {
		o.RateLimitDecreaseFactor = 0.9
	}
	if o.RateLimitIncreaseFactor <= 0 {
		o.RateLimitIncreaseFactor = 0.1
	}
	if o.RateLimitRecoveryInterval <= 0 {
		o.RateLimitRecoveryInterval = time.Second
	}
	if o.RateLimitUncapAfter <= 0 {
		o.RateLimitUncapAfter = 15 * time.Second
	}
	if o.HedgeMinDelay <= 0 {
		o.HedgeMinDelay = 100 * time.Millisecond
	}
	if o.HedgeLossWindow <= 0 {
		o.HedgeLossWindow = 10 * time.Second
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = 2
	}
	if o.AdaptiveTimeoutMin <= 0 {
		o.AdaptiveTimeoutMin = 300 * time.Millisecond
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 3
	}
	if o.RelayProbeInterval <= 0 {
		o.RelayProbeInterval = time.Second
	}
	if o.RelayTick <= 0 {
		o.RelayTick = 10 * time.Millisecond
	}
	if o.Logger == nil {
		o.Logger = nopLogger{}
	}
}
