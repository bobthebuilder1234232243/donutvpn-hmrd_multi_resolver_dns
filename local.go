package multidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// We own the underlying udp/tcp handles (StartLocal hands them to dns.Server
// pre-bound), and we close them directly on shutdown rather than relying on
// dns.Server.ShutdownContext. ShutdownContext bails early with "server not
// started" if the serve goroutine hasn't yet set srv.started=true — a race
// that triggers when StartLocal's caller Closes immediately after returning.
// Closing the raw handles unblocks Accept/ReadUDP no matter where the serve
// goroutine is, so the listeners always exit.

// StartLocal builds a Manager backed by a local UDP+TCP DNS listener on a
// free 127.0.0.1 port. The returned address ("127.0.0.1:NNNN") is what
// callers point their DNS client at — sing-box's dnstt outbound, for
// example, uses it as a single virtual resolver and lets the pool fan
// queries out across the registered upstreams.
//
// The listener is bound *before* this function returns (using pre-allocated
// net.PacketConn / net.Listener handed to dns.Server, avoiding the
// pick-port-then-bind TOCTOU window), so the address is immediately
// connectable. Closing the returned Manager tears the listener down.
func StartLocal(opts Options) (*Manager, string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("multidns: bind udp: %w", err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, "", fmt.Errorf("multidns: bind tcp on %s: %w", addr, err)
	}

	mgr := New(opts)
	handler := dns.HandlerFunc(makeLocalHandler(mgr))
	tcpSrv := &dns.Server{Listener: ln, Handler: handler}

	mgr.local = &localListener{
		tcp:         tcpSrv,
		udpConn:     pc,
		tcpListener: ln,
		addr:        addr,
	}

	// UDP goes straight through the relay: no unpacking, no goroutine and no
	// socket per query, the answer written back as soon as it arrives.
	mgr.local.wg.Add(2)
	go func() {
		defer mgr.local.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, client, err := pc.ReadFrom(buf)
			if err != nil {
				if !mgr.local.shuttingDown() {
					mgr.opts.Logger.Errorf("multidns: local udp listener exited: %v", err)
				}
				return
			}
			if n < 12 {
				continue
			}
			_ = mgr.relay.Submit(buf[:n], func(resp []byte) {
				_, _ = pc.WriteTo(resp, client)
			})
		}
	}()
	go func() {
		defer mgr.local.wg.Done()
		if err := tcpSrv.ActivateAndServe(); err != nil && !mgr.local.shuttingDown() {
			mgr.opts.Logger.Errorf("multidns: local tcp listener exited: %v", err)
		}
	}()

	return mgr, addr, nil
}

// localListener owns the dns.Server pair StartLocal stood up, plus the
// shutdown bookkeeping. A separate type keeps Manager small for the
// (still common) case where StartLocal isn't used.
type localListener struct {
	tcp         *dns.Server
	udpConn     net.PacketConn
	tcpListener net.Listener
	addr        string

	wg     sync.WaitGroup
	stopMu sync.Mutex
	stop   bool
}

func (l *localListener) shutdown() error {
	l.stopMu.Lock()
	if l.stop {
		l.stopMu.Unlock()
		return nil
	}
	l.stop = true
	l.stopMu.Unlock()

	var firstErr error
	if err := l.udpConn.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := l.tcpListener.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	l.wg.Wait()
	return firstErr
}

func (l *localListener) shuttingDown() bool {
	l.stopMu.Lock()
	defer l.stopMu.Unlock()
	return l.stop
}

// makeLocalHandler returns a dns.HandlerFunc that dispatches each incoming
// query through mgr.Resolve. Mirrors Server.handle but lives off the Server
// type so StartLocal can drive raw dns.Server instances directly.
func makeLocalHandler(mgr *Manager) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, q *dns.Msg) {
		deadline := mgr.opts.DefaultDeadline
		if deadline <= 0 {
			deadline = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()

		resp, err := mgr.Resolve(ctx, q)
		if err != nil || resp == nil {
			if !errors.Is(err, context.Canceled) {
				mgr.opts.Logger.Warnf("multidns: local resolve failed: %v", err)
			}
			fail := errResponse(q, dns.RcodeServerFailure)
			_ = w.WriteMsg(fail)
			return
		}
		resp.Id = q.Id
		if err := w.WriteMsg(resp); err != nil {
			mgr.opts.Logger.Warnf("multidns: local write failed: %v", err)
		}
	}
}
