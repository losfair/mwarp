package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	socks5Version = 0x05
	socks5MethodNoAuth = 0x00
	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03
	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04
	socks5RepSuccess = 0x00
)

// Dialer is the underlying transport used to reach the SOCKS5 server itself.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Socks5Client speaks SOCKS5 (CONNECT and UDP ASSOCIATE) to a single upstream
// server reached via the provided base dialer (typically a userspace WG net).
type Socks5Client struct {
	Server string
	Base   Dialer
}

// DialContext opens a TCP connection through the upstream proxy.
func (c *Socks5Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5 dial: unsupported network %q", network)
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	conn, err := c.Base.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 %s: %w", c.Server, err)
	}
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	}

	if err := socks5Greet(conn); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5WriteRequest(conn, socks5CmdConnect, host, uint16(port)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// UDPAssociate establishes a UDP relay session and returns a (Conn-like)
// session that wraps SOCKS5 UDP request/response framing.
func (c *Socks5Client) UDPAssociate(ctx context.Context) (*Socks5UDPSession, error) {
	ctrl, err := c.Base.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 %s: %w", c.Server, err)
	}
	if d, ok := ctx.Deadline(); ok {
		ctrl.SetDeadline(d)
	}
	if err := socks5Greet(ctrl); err != nil {
		ctrl.Close()
		return nil, err
	}
	// 0.0.0.0:0 means "any source", required by some servers.
	if err := socks5WriteRequest(ctrl, socks5CmdUDPAssociate, "0.0.0.0", 0); err != nil {
		ctrl.Close()
		return nil, err
	}
	addr, port, err := socks5ReadReply(ctrl)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	ctrl.SetDeadline(time.Time{})
	if addr == "" || addr == "0.0.0.0" {
		host, _, _ := net.SplitHostPort(c.Server)
		addr = host
	}
	relay := net.JoinHostPort(addr, strconv.FormatUint(uint64(port), 10))

	udp, err := c.Base.DialContext(ctx, "udp", relay)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("dial socks5 udp %s: %w", relay, err)
	}
	return &Socks5UDPSession{ctrl: ctrl, conn: udp}, nil
}

func socks5Greet(c net.Conn) error {
	// Single auth method: no auth.
	if _, err := c.Write([]byte{socks5Version, 1, socks5MethodNoAuth}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5 greet: bad version %d", resp[0])
	}
	if resp[1] != socks5MethodNoAuth {
		return fmt.Errorf("socks5 greet: server requires auth method %d", resp[1])
	}
	return nil
}

func socks5WriteRequest(c net.Conn, cmd byte, host string, port uint16) error {
	buf := []byte{socks5Version, cmd, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, socks5AddrIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, socks5AddrIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: domain too long")
		}
		buf = append(buf, socks5AddrDomain, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	buf = append(buf, p[:]...)
	_, err := c.Write(buf)
	return err
}

func socks5ReadReply(c net.Conn) (string, uint16, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", 0, err
	}
	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5 reply: bad version %d", head[0])
	}
	if head[1] != socks5RepSuccess {
		return "", 0, fmt.Errorf("socks5 reply: error code %d", head[1])
	}
	var addr string
	switch head[3] {
	case socks5AddrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		addr = net.IP(b[:]).String()
	case socks5AddrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		addr = net.IP(b[:]).String()
	case socks5AddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", 0, err
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(c, dom); err != nil {
			return "", 0, err
		}
		addr = string(dom)
	default:
		return "", 0, fmt.Errorf("socks5 reply: unknown atyp %d", head[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(pb[:])
	return addr, port, nil
}

// Socks5UDPSession is a UDP relay session. Each WriteTo wraps the payload in
// SOCKS5 UDP request format and sends it to the relay; ReadFrom strips it.
type Socks5UDPSession struct {
	ctrl net.Conn
	conn net.Conn
}

func (s *Socks5UDPSession) Close() error {
	_ = s.conn.Close()
	return s.ctrl.Close()
}

func (s *Socks5UDPSession) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *Socks5UDPSession) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// WriteTo sends a UDP datagram to dst via the relay.
func (s *Socks5UDPSession) WriteTo(p []byte, dst netip.AddrPort) (int, error) {
	hdr := make([]byte, 0, 22+len(p))
	hdr = append(hdr, 0x00, 0x00, 0x00) // RSV, RSV, FRAG
	if dst.Addr().Is4() {
		hdr = append(hdr, socks5AddrIPv4)
		v4 := dst.Addr().As4()
		hdr = append(hdr, v4[:]...)
	} else {
		hdr = append(hdr, socks5AddrIPv6)
		v6 := dst.Addr().As16()
		hdr = append(hdr, v6[:]...)
	}
	var pp [2]byte
	binary.BigEndian.PutUint16(pp[:], dst.Port())
	hdr = append(hdr, pp[:]...)
	hdr = append(hdr, p...)
	n, err := s.conn.Write(hdr)
	if err != nil {
		return 0, err
	}
	if n < len(hdr) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// ReadFrom reads a SOCKS5-wrapped datagram, strips the header, and reports
// the remote endpoint.
func (s *Socks5UDPSession) ReadFrom(buf []byte) (int, netip.AddrPort, error) {
	tmp := make([]byte, len(buf)+512)
	n, err := s.conn.Read(tmp)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 4 {
		return 0, netip.AddrPort{}, errors.New("socks5 udp: short header")
	}
	if tmp[2] != 0 {
		return 0, netip.AddrPort{}, errors.New("socks5 udp: fragmented packet not supported")
	}
	off := 4
	var addr netip.Addr
	switch tmp[3] {
	case socks5AddrIPv4:
		if n < off+4+2 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short ipv4")
		}
		var b [4]byte
		copy(b[:], tmp[off:off+4])
		addr = netip.AddrFrom4(b)
		off += 4
	case socks5AddrIPv6:
		if n < off+16+2 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short ipv6")
		}
		var b [16]byte
		copy(b[:], tmp[off:off+16])
		addr = netip.AddrFrom16(b)
		off += 16
	case socks5AddrDomain:
		if n < off+1 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short atyp domain")
		}
		l := int(tmp[off])
		off++
		if n < off+l+2 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short domain")
		}
		host := string(tmp[off : off+l])
		off += l
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("socks5 udp: domain reply not parseable: %s", host)
		}
		addr = ip
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("socks5 udp: unknown atyp %d", tmp[3])
	}
	port := binary.BigEndian.Uint16(tmp[off : off+2])
	off += 2
	payload := tmp[off:n]
	if len(payload) > len(buf) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}
	copy(buf, payload)
	return len(payload), netip.AddrPortFrom(addr, port), nil
}
