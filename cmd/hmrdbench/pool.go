package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	multidns "github.com/hiddify/hmrd_multi_resolver_dns"
)

// runPool serves the relay on a fixed local UDP address, in front of the
// given resolvers: a DNS tunnel client that takes one resolver (Slipstream,
// dnstt, ...) can then be pointed at it.
func runPool(args []string) error {
	fs := flag.NewFlagSet("pool", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:5353", "UDP address the tunnel client sends its queries to")
	lb := fs.String("lb", "auto", "load balance: auto, roundrobin, weighted or lowest_latency")
	stats := fs.Duration("stats", 0, "how often to log each resolver's state; 0 = never")
	var resolvers []string
	fs.Func("resolver", "resolver: host:port, udp://, tcp://, dot://host:853 or https://host/dns-query (repeatable)", func(v string) error {
		resolvers = append(resolvers, v)
		return nil
	})
	_ = fs.Parse(args)
	if len(resolvers) == 0 {
		return errors.New("at least one -resolver is required")
	}
	strategy := multidns.LBAuto
	switch strings.ToLower(*lb) {
	case "auto":
	case "roundrobin":
		strategy = multidns.LBRoundRobin
	case "weighted":
		strategy = multidns.LBWeighted
	case "lowest_latency":
		strategy = multidns.LBLowestLatency
	default:
		return fmt.Errorf("unknown load balance %q", *lb)
	}
	m := multidns.New(multidns.Options{LoadBalance: strategy})
	defer m.Close()
	for _, r := range resolvers {
		if _, err := m.AddResolverURL(r); err != nil {
			return fmt.Errorf("resolver %s: %w", r, err)
		}
	}
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return err
	}
	defer pc.Close()
	log.Printf("pool on %s over %d resolvers (%s)", pc.LocalAddr(), len(resolvers), *lb)
	if *stats > 0 {
		go func() {
			for range time.Tick(*stats) {
				for _, s := range m.Stats() {
					log.Printf("%s state=%s ok=%d refused=%d timeouts=%d sent=%d cap=%.1f/s", s.Name, s.State, s.ValidCount, s.RateLimited, s.TimeoutCount, s.Sent, float64(s.CurrentRPMCap)/60)
				}
			}
		}()
	}
	buf := make([]byte, 65535)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n < 12 {
			continue
		}
		_ = m.Submit(buf[:n], func(resp []byte) {
			_, _ = pc.WriteTo(resp, client)
		})
	}
}
