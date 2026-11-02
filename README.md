# hmrd_multi_resolver_dns

A standalone Go library that wraps a configurable set of upstream DNS
resolvers (UDP, TCP, DoT, DoH) behind one intelligent dispatcher. It is
designed to be embedded in [hiddify-sing-box][singbox] (and through it,
[hiddify-core][core]) as a more capable replacement for the current
single-upstream code path.

[singbox]: https://github.com/hiddify/hiddify-sing-box
[core]: https://github.com/hiddify/hiddify-core

## Why this exists

Real-world resolvers go down, get rate-limited, and recover. A fixed
primary/secondary scheme — or a static round-robin — wastes the caller's
deadline on a hung primary, ignores rate-limit signals, and never learns
when a failed upstream is healthy again.

This library makes those concerns first-class:

- Per-query retry on the next resolver while strictly respecting
  `ctx.Deadline`.
- **Hedged attempts**: a candidate that has not answered within a latency-derived delay keeps running while the next one is tried; the first answer wins and the losers are cancelled without being charged. A resolver that drops packets costs a fraction of its timeout, not all of it.
- Failure classifier feeds an **AIMD throttle** per resolver; rate-limit
  signals (`REFUSED`, `SERVFAIL`, HTTP 429) cut the cap, sustained success
  grows it back. No operator pre-tuning.
- Down resolvers get **probed in the background** with the very query
  that triggered the outage — cheapest way to detect recovery without
  polluting live traffic.
- Every transport accepts a custom `DialFunc`, so an embedder (e.g.
  hiddify-sing-box) can route DNS through a tunnel.

The reference implementation that inspired several mechanics
(Rcode-based rate-limit detection, decaying counters, probing unhealthy
resolvers) is [vaydns PR #64][vaydns], but `vaydns.MultiResolver` is a
`net.PacketConn` bolted onto a single tunnel. This library is a
first-class DNS proxy with per-query semantics.

[vaydns]: https://github.com/net2share/vaydns/pull/64

## Features

| Feature | Where |
|---|---|
| UDP / TCP / DoT / DoH upstreams | `resolver.go` |
| Deadline-aware retry across candidates | `pool.go` |
| AIMD rate-limit throttling per resolver | `health.go`, `ratelimit.go` |
| Background recovery probing using the failing query | `prober.go` |
| Asynchronous relay for DNS tunnels: one long-lived socket per resolver, ID rewriting, instant fallback, pacing, hedging, probing with live queries, fanout | `relay.go` |
| Auto (capacity-aware) / round-robin / weighted / lowest-latency LB strategies | `relay.go`, `pool.go` |
| Dynamic `AddResolver` / `RemoveResolver` at runtime | `multidns.go` |
| Custom `DialFunc` injection on every transport | `resolver.go` |
| Optional UDP+TCP DNS server listener | `server.go` |
| `net.PacketConn` surface for DNS-tunnel integrations | `packetconn.go` |

## Install

```bash
go get github.com/hiddify/hmrd_multi_resolver_dns
```

Requires Go 1.25+. Wire format via [`miekg/dns`][miekg].

[miekg]: https://github.com/miekg/dns

## Usage — programmatic

```go
import (
    "context"
    "log"

    "github.com/miekg/dns"
    multidns "github.com/hiddify/hmrd_multi_resolver_dns"
)

mgr := multidns.New(multidns.Options{
    DefaultDeadline:        5 * time.Second, // overall query deadline
    DefaultResolverTimeout: 2 * time.Second, // per-attempt cap (failover budget)
    LoadBalance:            multidns.LBRoundRobin,
    ProbeInterval:          5 * time.Second,
})
defer mgr.Close()

mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoUDP,
    Address:  "1.1.1.1:53",
})
mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoDoH,
    Address:  "https://cloudflare-dns.com/dns-query",
})
mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoDoT,
    Address:  "1.1.1.1:853",
})

q := new(dns.Msg)
q.SetQuestion("example.com.", dns.TypeA)
resp, err := mgr.Resolve(context.Background(), q)
if err != nil {
    log.Fatal(err)
}
log.Printf("got %d answers", len(resp.Answer))
```

## Usage — built-in DNS server

```go
mgr := multidns.New(multidns.Options{ /* ... */ })
mgr.AddResolver( /* ... */ )

srv := mgr.NewServer(":5353") // UDP+TCP by default; pass "udp" or "tcp" to limit
go srv.ListenAndServe()
defer srv.Shutdown(context.Background())
```

Then `dig @127.0.0.1 -p 5353 example.com` resolves through the pool.

A runnable demo CLI lives at [`example/main.go`](example/main.go):

```bash
go run ./example \
    -listen :5353 \
    -upstream udp://1.1.1.1:53 \
    -upstream udp://8.8.8.8:53 \
    -upstream dot://1.1.1.1:853 \
    -upstream doh://https://cloudflare-dns.com/dns-query \
    -stats 5s
```

## The relay: the high-throughput path for DNS tunnels

`Resolve` runs one synchronous exchange per attempt, which suits a stub
resolver. A DNS tunnel sends hundreds of queries a second and keeps many in
flight, so `StartLocal`'s UDP listener, `PacketConn` and `Manager.Submit` use
the relay instead (`relay.go`):

- **One long-lived socket per UDP resolver**, opened through the resolver's
  `Dialer` when set. Query IDs are rewritten to multiplex every client query
  over it, and restored on the answer. No goroutine, socket or unpacking per
  query; TCP, DoT and DoH resolvers run an exchange per attempt.
- **Capacity-aware scheduling** (`LBAuto`). Each resolver's rate cap is
  learned from what it really answers: on a refusal, or a run of drops while
  it still answers others, the cap becomes 90% of its recent success rate,
  and it grows 10% a second while the resolver keeps answering. Queries go
  where there is spare capacity, so a resolver limited to 20 queries a second
  gets about a third of what a 60 one gets, and the total approaches the sum
  of their limits.
- **Instant fallback.** A `REFUSED` or `SERVFAIL` answer is retried at once on
  another resolver, up to `MaxAttempts` resolvers per query.
- **Overflow in proportion.** A query that finds every resolver at its cap is
  sent at once to the resolver with the most capacity left relative to its
  cap, so the overflow is spread like the rest. Waiting would add delay to
  every query of a saturated tunnel, which costs more than the refusal it
  retransmits; `PacingMaxWait` turns waiting on for clients that prefer it.
- **Timeouts like TCP's.** Each attempt gets the resolver's mean latency plus
  four deviations, so a lossy resolver is given up quickly while a tunnel
  server that holds polls for a second is not mistaken for a lossy one.
- **Hedging only where it pays.** A resolver that lost packets in the last
  `HedgeLossWindow` has its unanswered queries also sent to another resolver
  after its mean latency plus two deviations; a healthy one is never hedged,
  so no quota is spent on second copies.
- **Probing with live queries.** A down resolver gets a copy of a live query
  every `RelayProbeInterval` and is back in service on its first answer.
- **Fanout.** `SpreadCount` sends every query to several resolvers (`-1`: all)
  and keeps the first answer.

The first answer wins and later ones are dropped. A query no resolver
answered gets the last error answer, or `SERVFAIL`, so the client can retry.

```go
mgr, addr, err := multidns.StartLocal(multidns.Options{LoadBalance: multidns.LBAuto})
// point the tunnel at addr; add resolvers with mgr.AddResolverURL("8.8.8.8")
_ = mgr.Submit(wireQuery, func(answer []byte) { /* answer carries wireQuery's ID */ })
```

## Benchmark

`cmd/hmrdbench` measures how many queries a second each approach gets answered
through rate-limited, dead, slow and lossy resolvers. It needs nothing but Go:

```bash
go run ./cmd/hmrdbench bench                    # every scenario, about 9 minutes
go run ./cmd/hmrdbench bench -scenarios three-limited -duration 10s -v
```

It starts the resolvers in-process (UDP, 20 ms latency plus up to 10 ms of
jitter unless the scenario sets another) and drives each approach with 64
queries in flight in a closed loop, like a DNS tunnel's window: a worker sends
its next query when the previous one is answered, or 200 ms after it failed,
like a retransmission timer. A query counts as answered on a `NOERROR` answer.
The approaches:

- **auto (relay)**: `Submit` with `LBAuto`, the path a DNS tunnel uses through
  `StartLocal` or `PacketConn`;
- **round robin (relay)**: the same with `LBRoundRobin`;
- **Resolve (sync)**: `Manager.Resolve`, a synchronous exchange per query;
- **plain multi-resolver**: one socket per resolver, round robin, no retry and
  no rate awareness, as most clients' multi-resolver support works;
- **single resolver**: the first resolver alone.

Answered queries per second, 15 s per run:

| Resolvers | auto (relay) | round robin (relay) | Resolve (sync) | plain multi-resolver | single resolver |
|---|---|---|---|---|---|
| 1 unlimited | **2528** | 2539 | 2521 | 2543 | 2541 |
| 1 limited to 30/s | **31.9** | 31.9 | 31.9 | 31.9 | 31.9 |
| 3 unlimited | **2542** | 2546 | 2523 | 2538 | 2541 |
| 3 limited: 20/s and 30/s refusing, 40/s dropping | **96.3** | 96.8 | 63.7 | 95.6 | 21.3 |
| 30/s refusing, 40/s dropping, 1 dead | **73.5** | 71.1 | 62.0 | 60.0 | 31.9 |
| 3 unlimited, 20, 100 and 400 ms | **2400** | 362 | 883 | 362 | 2540 |
| 3 unlimited, 0%, 10% and 30% loss | **2429** | 2416 | 2444 | 189 | 2545 |

Where the resolvers differ only in their rate limits, the relay and a plain
multi-resolver both keep every resolver saturated and reach the same ceiling,
the sum of the limits. The relay pulls ahead when resolvers differ in ways round
robin cannot see: a dead resolver, uneven latency (it sends the traffic to the
fast resolver instead of making a third of the queries wait 400 ms) and packet
loss (it retries and hedges instead of waiting out a timeout).

`hmrdbench resolver` runs one such resolver as a server, forwarding the names of
a tunnel domain to a tunnel server, `hmrdbench http` serves a download and
upload target, and `hmrdbench pool -listen 127.0.0.1:5353 -resolver a
-resolver b` serves the relay on a local address, for tunnel clients that are
not written in Go (Slipstream). hiddify-sing-box uses them in its end-to-end
tunnel benchmark, `test/dnstunnel-bench`.

## Usage — as a `net.PacketConn` for DNS-tunnel protocols

DNS-tunnel protocols like [dnstt](https://github.com/net2share/vaydns) (used by hiddify) speak raw DNS wire format to a recursive resolver and care most about *delivery reliability* — if the resolver they're using gets rate-limited or blocked, the whole tunnel stalls. The library exposes its smart pool as a `net.PacketConn` so it can drop in wherever such a protocol expects one:

```go
mgr := multidns.New(multidns.Options{ /* ... */ })
mgr.AddResolver( /* recursive resolver A */ )
mgr.AddResolver( /* recursive resolver B */ )
mgr.AddResolver( /* recursive resolver C */ )

conn := mgr.PacketConn()                // implements net.PacketConn
defer conn.Close()                      // does NOT close mgr — caller owns mgr

// hand `conn` to the tunnel/protocol that wants a net.PacketConn
tunnel.SetResolverConn(conn)
```

Semantics: `WriteTo(buf, _)` unpacks `buf` as a DNS query and dispatches it asynchronously through the pool (smart selection, AIMD throttling, recovery probing all apply). The response — when one comes — surfaces on the next `ReadFrom`. `SetReadDeadline` / `SetWriteDeadline` are honored. Closing the conn does not close the underlying Manager, so direct `Resolve` calls and other PacketConns can keep using the same pool.

## Usage — embedded with a custom Dialer

This is the integration point for hiddify-sing-box. Each resolver can
carry its own `DialFunc`, which is wired into the transport (UDP/TCP/DoT
get it via `dns.Client.Dialer`; DoH gets it via the `http.Transport.DialContext`).

```go
import "github.com/sagernet/sing/common/network"

mgr.AddResolver(multidns.ResolverConfig{
    Protocol: multidns.ProtoUDP,
    Address:  "1.1.1.1:53",
    Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
        // Route DNS through a sing-box outbound, an SSH tunnel, a SOCKS5
        // proxy — whatever produces a net.Conn for (network, addr).
        return tunneledDial(ctx, network, addr)
    },
})
```

## Configuration reference

### `Options`

| Field | Default | Notes |
|---|---|---|
| `DefaultDeadline` | 5s | Applied when the caller's `ctx` has no deadline. |
| `DefaultResolverTimeout` | 2s | Per-attempt cap. Smaller than `DefaultDeadline` so failover fits inside one query. |
| `LoadBalance` | `LBRoundRobin` | `LBAuto` / `LBRoundRobin` / `LBWeighted` / `LBLowestLatency`. `LBAuto` sends each query to the resolver with the most spare capacity (power of two choices over in-flight queries, latency and loss, within each resolver's learned rate cap); use it for DNS tunnels. |
| `ProbeInterval` | 5s | How often a `down` resolver is re-tried with its failing query. |
| `DownAfterFailures` | 8 | Consecutive timeout/network failures before a resolver is moved to `down`. |
| `RateLimitFloorRPM` | 6 | Hard floor for the cap. |
| `RateLimitUncapRPM` | 60000 | A cap that grows past this is lifted at once. The default is far above any resolver, so caps are lifted by `RateLimitUncapAfter`. |
| `RateLimitAdditive` | 5 | Smallest step the cap grows by per recovery interval. |
| `RateLimitWindow` | 3s | How far back the success rate is measured when a resolver refuses. |
| `RateLimitDecreaseFactor` | 1.2 | On a refusal the cap becomes this many times the resolver's answer rate over `RateLimitWindow`, overflow included. Above 1 keeps a refusing resolver saturated: a refusal comes back at once and costs only a retry. A burst of refusals within one recovery interval counts once. |
| `RateLimitDropFactor` | 1.15 | The same when a resolver drops queries while it still answers others: a little above its answer rate so it can show it takes more, but less than for refusals, as a dropped query costs the client a whole timeout. |
| `RateLimitIncreaseFactor` | 0.1 | Share of the cap added every recovery interval without a refusal. |
| `RateLimitRecoveryInterval` | 1s | How often the cap grows while the resolver keeps answering. |
| `RateLimitUncapAfter` | 15s | The cap is lifted once no refusal has been seen for this long. |
| `HedgeDelay` | 0 (adaptive) | Wait before the same query is also sent to the next candidate. Adaptive: a resolver that lost packets within `HedgeLossWindow` is hedged after its mean latency plus two deviations, within [`HedgeMinDelay`, attempt timeout]; one with no recent loss gets its whole attempt timeout, so a rate-limited resolver's quota is not spent on second copies. |
| `HedgeMinDelay` | 100ms | Lower bound of the adaptive hedge delay. |
| `HedgeLossWindow` | 10s | How far back a timeout makes a resolver "lossy" for hedging. |
| `MaxInFlight` | 2 | Attempts of one query that may run at once. |
| `DisableHedging` | false | Strictly sequential attempts. |
| `AdaptiveTimeoutMin` | 300ms | Lower bound of the adaptive per-attempt timeout (mean latency plus four deviations, never above the resolver's `Timeout`). |
| `DisableAdaptiveTimeout` | false | Always use the resolver's full `Timeout` per attempt. |
| `MaxAttempts` | 3 | Resolvers one relayed query is sent to, retries and hedges included. |
| `SpreadCount` | 1 | Copies of every relayed query sent at once to different resolvers; `-1` sends to all. |
| `PacingMaxWait` | 0 | When set, how long a relayed query waits for a resolver under its cap before it is sent anyway. 0 sends at once to the resolver with the most capacity left. |
| `RelayProbeInterval` | 1s | How often a down resolver gets a copy of a live query. |
| `RelayTick` | 10ms | Timer of the relay's timeouts, hedges and pacing. |
| `Logger` | no-op | Adapter to your logging system; `log/slog`-friendly shape. |

### `ResolverConfig`

| Field | Notes |
|---|---|
| `Protocol` | `ProtoUDP` \| `ProtoTCP` \| `ProtoDoT` \| `ProtoDoH`. |
| `Address` | `host:port` for UDP/TCP/DoT; full `https://` URL for DoH. |
| `Timeout` | Per-attempt cap; falls back to `Options.DefaultResolverTimeout`. |
| `TLSConfig` | DoT/DoH only. SNI is auto-derived from `Address` if unset. |
| `Dialer` | Optional `DialFunc` for routing through a tunnel. |
| `Weight` | `LBWeighted` only; `0` ⇒ pure fallback. |
| `Name` | Optional friendly id surfaced in stats. |
| `InitialRPM` | Optional starting throttle cap; `0` ⇒ uncapped. |

## How it decides things

1. **Selecting a candidate.** `pool.candidates()` snapshots the current
   resolvers, drops anything in `down`, and orders the rest per
   `LoadBalance`. `LBLowestLatency` prefers unmeasured resolvers first
   (so newcomers get sampled), then ascending EWMA. `LBWeighted` runs a
   weighted random shuffle; weight 0 means pure fallback.
2. **Sending.** Each candidate's token bucket gates throughput at
   `currentRPMCap` (0 = uncapped). If the bucket rejects, the pool moves
   to the next candidate. If every candidate is throttled, we force
   exactly one through — never N — so AIMD isn't amplified by N×.
3. **Per-attempt timeout.** `min(ResolverConfig.Timeout, ctx.deadline-now)`
   is applied so a hung resolver can't burn the whole query budget.
4. **Classifying the result.** `failNone` / `failTimeout` / `failNetwork`
   / `failRateLimit` / `failBadResponse`. `failBadResponse` (e.g.
   `FormErr` from the upstream) does **not** penalize the resolver.
   `failRateLimit` triggers AIMD multiplicative-decrease on the cap.
   N consecutive `failTimeout`/`failNetwork` push the resolver to `down`
   and stash the offending query.
5. **Recovery.** A per-resolver goroutine wakes every `ProbeInterval`
   while the resolver is `down`, replays the stashed query (off the hot
   path, bypassing the bucket). On a valid response the cap resets to 0
   and state returns to `healthy`.

## Testing

```bash
go test -race -count=1 ./...   # 39 tests, ~3s wall clock
go vet ./...
```

Coverage includes:

- Per-protocol roundtrips against real in-process UDP/TCP/DoT/DoH
  servers (self-signed certs).
- Failover within a tight overall deadline, with one upstream that
  drops every packet.
- Rate-limit AIMD progression (Rcode REFUSED) and DoH HTTP-429.
- Down → prober → healthy cycle, verifying the prober uses the failing
  query.
- `AddResolver` / `RemoveResolver` under live traffic.
- Custom `DialFunc` invoked on every transport (UDP/TCP/DoT/DoH).
- Concurrent lifecycle stress (`AddResolver` ↔ `Close` 50× under -race).
- All six findings from the initial code review have a regression test
  in [`review_fixes_test.go`](review_fixes_test.go).

## Status

Pre-1.0 — API may shift before the first tagged release. The shapes most
likely to change: `Options` field names and the `Logger` interface (to
align with whatever the embedder uses).

## License

TBD — match the parent project's license once selected.
