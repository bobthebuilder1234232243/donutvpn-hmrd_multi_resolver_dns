package multidns

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// PacketConn returns a net.PacketConn that speaks raw DNS wire format and
// dispatches every WriteTo into the Manager's pool. This exists so the
// library can be plugged in anywhere a net.PacketConn-shaped DNS resolver is
// expected — most importantly as the conn that vaydns/dnstt's tunnel speaks
// over (replacing vaydns's built-in MultiResolver), so dnstt's tunnel rides
// on top of the smart pool's failover, AIMD throttling, and recovery probing.
//
// Lifecycle: the returned PacketConn does NOT take ownership of mgr — the
// caller must Close the Manager separately when done. Closing the
// PacketConn only stops its read pump; the Manager and its upstreams stay
// usable for direct Resolve calls.
func (m *Manager) PacketConn() net.PacketConn {
	return newPacketConn(m)
}

// NewPacketConn is a free-function alias of (*Manager).PacketConn for
// callers who prefer a constructor-style API.
func NewPacketConn(m *Manager) net.PacketConn {
	return m.PacketConn()
}

type packetConn struct {
	mgr     *Manager
	recvCh  chan []byte
	closed  chan struct{}
	closeMu sync.Mutex
	wg      sync.WaitGroup

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
}

func newPacketConn(mgr *Manager) *packetConn {
	return &packetConn{
		mgr:    mgr,
		recvCh: make(chan []byte, 4096),
		closed: make(chan struct{}),
	}
}

// WriteTo unpacks buf as a DNS query, dispatches it asynchronously through
// the Manager pool, and returns immediately. The response (if any) will land
// on a future ReadFrom call. The destination address is ignored — the pool
// picks which resolver actually receives the packet.
//
// This async dispatch matches the net.PacketConn contract that callers like
// vaydns expect: WriteTo enqueues, ReadFrom drains. Synchronous request /
// response semantics are still available via Manager.Resolve for callers
// who don't need PacketConn shape.
func (p *packetConn) WriteTo(buf []byte, _ net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}

	if dl := p.writeDeadline.Load(); dl != nil && !dl.IsZero() && !time.Now().Before(*dl) {
		return 0, &timeoutErr{}
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
		return 0, err
	}

	// The relay copies buf; the answer lands on a later ReadFrom. A full
	// receive queue drops the answer, as a UDP socket would: blocking here
	// would stall the relay for every other query.
	if err := p.mgr.relay.Submit(buf, func(resp []byte) {
		select {
		case p.recvCh <- resp:
		case <-p.closed:
		default:
		}
	}); err != nil {
		return 0, err
	}
	return len(buf), nil
}

// ReadFrom blocks until either a response arrives, the read deadline fires,
// or the conn is closed. The returned net.Addr is a placeholder (DNS
// responses don't have a meaningful peer address from the consumer's point
// of view here — the pool decides which upstream actually answered).
func (p *packetConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	var deadlineCh <-chan time.Time
	if dl := p.readDeadline.Load(); dl != nil && !dl.IsZero() {
		t := time.NewTimer(time.Until(*dl))
		defer t.Stop()
		deadlineCh = t.C
	}

	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case <-deadlineCh:
		return 0, nil, &timeoutErr{}
	case msg := <-p.recvCh:
		n := copy(buf, msg)
		return n, packetConnAddr{}, nil
	}
}

// Close stops the read pump and drains pending dispatch goroutines. It does
// NOT close the underlying Manager — callers that own the Manager are
// responsible for that.
func (p *packetConn) Close() error {
	p.closeMu.Lock()
	select {
	case <-p.closed:
		p.closeMu.Unlock()
		return nil
	default:
		close(p.closed)
	}
	p.closeMu.Unlock()
	p.wg.Wait()
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return packetConnAddr{} }

func (p *packetConn) SetDeadline(t time.Time) error {
	p.readDeadline.Store(&t)
	p.writeDeadline.Store(&t)
	return nil
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.readDeadline.Store(&t)
	return nil
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.Store(&t)
	return nil
}

// packetConnAddr is a placeholder net.Addr — the underlying upstream that
// served any given response is selected dynamically by the pool, so a fixed
// peer address would be misleading. Callers (notably vaydns) only use the
// addr for sanity logging; this satisfies that.
type packetConnAddr struct{}

func (packetConnAddr) Network() string { return "multidns" }
func (packetConnAddr) String() string  { return "multidns:pool" }

// timeoutErr satisfies net.Error so callers (including vaydns's turbotunnel
// pump) can distinguish a deadline event from a hard close.
type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "multidns: i/o deadline exceeded" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
