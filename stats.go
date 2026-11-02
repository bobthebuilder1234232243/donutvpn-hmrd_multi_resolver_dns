package multidns

import "time"

// ResolverInfo is a static description of a registered resolver.
type ResolverInfo struct {
	ID       string
	Name     string
	Protocol Protocol
	Address  string
	Weight   int
}

// ResolverStat is a runtime snapshot of one resolver's health and counters.
type ResolverStat struct {
	ID            string
	Name          string
	State         string
	ValidCount    int64
	InvalidCount  int64
	TimeoutCount  int64
	RateLimited   int64
	CurrentRPMCap int
	RecentRPM     int
	InFlight      int64
	Sent          int64
	LossRate      float64
	LatencyEWMA   time.Duration
	LastValid     time.Time
	LastFail      time.Time
}
