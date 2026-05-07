package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// TCPBind is a wireguard-go conn.Bind that tunnels WireGuard's UDP datagrams
// over a single long-lived TCP connection using Mullvad-compatible
// `udp-over-tcp` framing: each datagram is preceded by a 16-bit big-endian
// length prefix.
//
// There is exactly one peer per TCPBind (matching the udp2tcp invariant). The
// underlying TCP connection is reopened transparently on I/O failure as long
// as the bind is open. WireGuard's Device.BindUpdate() may call Close() and
// then Open() — that lifecycle is supported.
type TCPBind struct {
	address     string
	dialTimeout time.Duration

	mu      sync.Mutex
	open    bool        // true between Open() and Close()
	conn    net.Conn    // current TCP conn; nil if not connected yet or torn down
	connGen uint64      // increments on each (re)dial; lets retries skip if someone else already reconnected
}

func NewTCPBind(address string) *TCPBind {
	return &TCPBind{
		address:     address,
		dialTimeout: 15 * time.Second,
	}
}

func (b *TCPBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true
	gen := b.connGen
	b.mu.Unlock()

	if err := b.dial(gen); err != nil {
		// failed to dial; revert open=true so a retry from BindUpdate
		// can try again.
		b.mu.Lock()
		b.open = false
		b.mu.Unlock()
		return nil, 0, fmt.Errorf("tcpbind dial %s: %w", b.address, err)
	}
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *TCPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	return nil
}

func (b *TCPBind) SetMark(uint32) error { return nil }
func (b *TCPBind) BatchSize() int       { return 1 }
func (b *TCPBind) ParseEndpoint(string) (conn.Endpoint, error) {
	// We only ever talk to one peer (the configured TCP endpoint). We
	// fabricate a dummy endpoint; WG just round-trips it through Send()
	// and Receive(), so its concrete value doesn't matter.
	return tcpEndpoint{}, nil
}

// dial establishes a fresh TCP connection. If staleGen != 0 and another
// caller has already reconnected (connGen advanced), this is a no-op.
func (b *TCPBind) dial(staleGen uint64) error {
	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		return net.ErrClosed
	}
	if staleGen != 0 && staleGen != b.connGen {
		b.mu.Unlock()
		return nil
	}
	if b.conn != nil {
		_ = b.conn.Close()
		b.conn = nil
	}
	addr := b.address
	timeout := b.dialTimeout
	b.mu.Unlock()

	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		_ = c.Close()
		return net.ErrClosed
	}
	b.conn = c
	b.connGen++
	b.mu.Unlock()
	return nil
}

func (b *TCPBind) currentConn() (net.Conn, uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn, b.connGen, b.open
}

func (b *TCPBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, p := range bufs {
		if len(p) > 65535 {
			return fmt.Errorf("tcpbind: packet too large (%d > 65535)", len(p))
		}
		if err := b.sendOne(p); err != nil {
			return err
		}
	}
	return nil
}

func (b *TCPBind) sendOne(p []byte) error {
	// Combine header + payload into a single Write so the framing header
	// never lands in its own TCP segment.
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)

	for attempt := 0; attempt < 3; attempt++ {
		c, gen, isOpen := b.currentConn()
		if !isOpen {
			return net.ErrClosed
		}
		if c == nil {
			if err := b.dial(0); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return err
				}
				continue
			}
			continue
		}
		if _, err := c.Write(buf); err != nil {
			_ = b.dial(gen)
			continue
		}
		return nil
	}
	return fmt.Errorf("tcpbind: send failed after retries")
}

// receive reads framed datagrams from the shared TCP connection. Returns
// net.ErrClosed iff Close() has been called.
func (b *TCPBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	c, gen, isOpen := b.currentConn()
	if !isOpen {
		return 0, net.ErrClosed
	}
	if c == nil {
		if err := b.dial(0); err != nil {
			return 0, err
		}
		c, gen, isOpen = b.currentConn()
		if !isOpen {
			return 0, net.ErrClosed
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		if !b.isOpen() {
			return 0, net.ErrClosed
		}
		_ = b.dial(gen)
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		sizes[0] = 0
		eps[0] = tcpEndpoint{}
		return 1, nil
	}
	if n > len(packets[0]) {
		// Drain the oversized frame so we stay in sync, then surface an
		// error. WG buffers are usually well above any sensible WG MTU.
		discard := make([]byte, n)
		_, _ = io.ReadFull(c, discard)
		return 0, fmt.Errorf("tcpbind: oversized frame %d > buffer %d", n, len(packets[0]))
	}
	if _, err := io.ReadFull(c, packets[0][:n]); err != nil {
		if !b.isOpen() {
			return 0, net.ErrClosed
		}
		_ = b.dial(gen)
		return 0, err
	}
	sizes[0] = n
	eps[0] = tcpEndpoint{}
	return 1, nil
}

func (b *TCPBind) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

// tcpEndpoint is a placeholder endpoint — there's exactly one peer per bind
// and routing decisions don't depend on its contents.
type tcpEndpoint struct{}

func (tcpEndpoint) ClearSrc()           {}
func (tcpEndpoint) SrcToString() string { return "" }
func (tcpEndpoint) DstToString() string { return "udp-over-tcp" }
func (tcpEndpoint) DstToBytes() []byte  { return []byte{0, 0, 0, 0, 0, 0} }
func (tcpEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (tcpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// resolveTCPEndpoint resolves host:port at startup so we fail fast on
// configuration errors and don't hammer DNS on each reconnect.
func resolveTCPEndpoint(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("invalid port %q: %w", port, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return s, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	return net.JoinHostPort(addrs[0], port), nil
}
