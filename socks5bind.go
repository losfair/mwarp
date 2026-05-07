package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Socks5Bind is a wireguard-go conn.Bind that sends WireGuard UDP datagrams
// through an outer SOCKS5 UDP ASSOCIATE relay.
type Socks5Bind struct {
	proxy       *Socks5Client
	dialTimeout time.Duration

	mu      sync.Mutex
	session *Socks5UDPSession
	open    bool
}

func NewSocks5Bind(proxy *Socks5Client) *Socks5Bind {
	return &Socks5Bind{
		proxy:       proxy,
		dialTimeout: 15 * time.Second,
	}
}

func (b *Socks5Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), b.dialTimeout)
	defer cancel()
	session, err := b.proxy.UDPAssociate(ctx)
	if err != nil {
		b.mu.Lock()
		b.open = false
		b.mu.Unlock()
		return nil, 0, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		_ = session.Close()
		return nil, 0, net.ErrClosed
	}
	b.session = session
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *Socks5Bind) Close() error {
	b.mu.Lock()
	b.open = false
	session := b.session
	b.session = nil
	b.mu.Unlock()
	if session != nil {
		return session.Close()
	}
	return nil
}

func (b *Socks5Bind) SetMark(uint32) error { return nil }
func (b *Socks5Bind) BatchSize() int       { return 1 }

func (b *Socks5Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	ep := socks5Endpoint{
		host: host,
		port: uint16(port),
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		ep.addr = netip.AddrPortFrom(addr, uint16(port))
	}
	return ep, nil
}

func (b *Socks5Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst, ok := ep.(socks5Endpoint)
	if !ok {
		if dstPtr, ok := ep.(*socks5Endpoint); ok {
			dst = *dstPtr
		} else {
			return conn.ErrWrongEndpointType
		}
	}
	session, ok := b.currentSession()
	if !ok {
		return net.ErrClosed
	}
	for _, p := range bufs {
		if _, err := session.WriteToHost(p, dst.host, dst.port); err != nil {
			return err
		}
	}
	return nil
}

func (b *Socks5Bind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	session, ok := b.currentSession()
	if !ok {
		return 0, net.ErrClosed
	}
	n, src, err := session.ReadFrom(packets[0])
	if err != nil {
		if !b.isOpen() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	sizes[0] = n
	eps[0] = newSocks5EndpointFromAddrPort(src)
	return 1, nil
}

func (b *Socks5Bind) currentSession() (*Socks5UDPSession, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session, b.open && b.session != nil
}

func (b *Socks5Bind) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

type socks5Endpoint struct {
	host string
	port uint16
	addr netip.AddrPort
}

func (e socks5Endpoint) ClearSrc()           {}
func (e socks5Endpoint) SrcToString() string { return "" }
func (e socks5Endpoint) DstToString() string {
	return net.JoinHostPort(e.host, strconv.FormatUint(uint64(e.port), 10))
}
func (e socks5Endpoint) DstToBytes() []byte {
	if e.addr.IsValid() {
		b, _ := e.addr.MarshalBinary()
		return b
	}
	return []byte(e.DstToString())
}
func (e socks5Endpoint) DstIP() netip.Addr {
	if e.addr.IsValid() {
		return e.addr.Addr()
	}
	return netip.Addr{}
}
func (e socks5Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

var _ conn.Bind = (*Socks5Bind)(nil)

func newSocks5EndpointFromAddrPort(addr netip.AddrPort) socks5Endpoint {
	return socks5Endpoint{
		host: addr.Addr().String(),
		port: addr.Port(),
		addr: addr,
	}
}

func newOuterSocks5Client(server string) *Socks5Client {
	return &Socks5Client{
		Server: server,
		Base:   &net.Dialer{},
	}
}

func validateOuterSocks5(server string) error {
	if server == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return fmt.Errorf("invalid outer socks5 address %q: %w", server, err)
	}
	return nil
}
