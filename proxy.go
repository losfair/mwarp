package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// RunProxy starts a SOCKS5 server in the parent ns. Accepted connections are
// dialed from inside the egress netns, whose only off-box egress is the warp
// iface — so traffic structurally cannot leak around warp.
func RunProxy(ctx context.Context, ns *NetNS, listenAddr string, logger *zap.Logger) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	defer ln.Close()
	logger.Info("socks5 proxy listening", zap.String("addr", ln.Addr().String()))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Warn("accept failed", zap.Error(err))
			continue
		}
		go handleProxyConn(ctx, ns, c, logger)
	}
}

func handleProxyConn(ctx context.Context, ns *NetNS, c net.Conn, logger *zap.Logger) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	// greet
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != socks5Version {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// We only support no-auth.
	if _, err := c.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
		return
	}

	// request
	var rh [4]byte
	if _, err := io.ReadFull(c, rh[:]); err != nil {
		return
	}
	if rh[0] != socks5Version || rh[1] != socks5CmdConnect {
		writeSocks5Reply(c, 0x07) // command not supported
		return
	}
	host, err := readSocks5Addr(c, rh[3])
	if err != nil {
		writeSocks5Reply(c, 0x01)
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	target := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	c.SetDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	upstream, dialErr := dialInNS(dialCtx, ns, target)
	if dialErr != nil {
		logger.Debug("proxy dial failed",
			zap.String("dst", target),
			zap.Error(dialErr))
		writeSocks5Reply(c, 0x05) // connection refused
		return
	}
	defer upstream.Close()

	// reply success with bound 0.0.0.0:0 (clients usually ignore).
	if _, err := c.Write([]byte{socks5Version, 0x00, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	logger.Debug("proxy open", zap.String("dst", target))
	pipe(c, upstream)
	logger.Debug("proxy close", zap.String("dst", target))
}

func writeSocks5Reply(c net.Conn, code byte) {
	c.Write([]byte{socks5Version, code, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
}

func readSocks5Addr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socks5AddrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case socks5AddrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	case socks5AddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(c, dom); err != nil {
			return "", err
		}
		return string(dom), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

// dialInNS opens a TCP connection to dst from inside ns. Resolution is also
// done in the netns via the standard resolver (so it goes through the netns
// DNS / warp path).
func dialInNS(ctx context.Context, ns *NetNS, dst string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan dialResult, 1)

	go func() {
		err := ns.Run(func() error {
			ips, err := resolveInNS(ctx, host)
			if err != nil {
				resCh <- dialResult{err: fmt.Errorf("resolve %s: %w", host, err)}
				return nil
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := connectInNS(ctx, ip, uint16(port))
				if err == nil {
					resCh <- dialResult{conn: conn}
					return nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no addresses for %s", host)
			}
			resCh <- dialResult{err: lastErr}
			return nil
		})
		if err != nil {
			resCh <- dialResult{err: err}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resCh:
		return r.conn, r.err
	}
}

// resolveInNS performs DNS resolution from the calling thread (which must be
// in the target netns). Uses the standard library resolver, which respects
// /etc/resolv.conf as seen by the current mnt ns — which we set up to point
// to the configured nameserver when joining via Run().
func resolveInNS(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	r := &net.Resolver{PreferGo: false}
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, a := range ips {
		out = append(out, a.IP)
	}
	return out, nil
}

// connectInNS opens a TCP socket in the current netns and connects
// synchronously. Returns the conn as a *net.TCPConn (via FileConn so it
// integrates with Go's runtime poller).
func connectInNS(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
	var (
		family int
		sa     unix.Sockaddr
	)
	if v4 := ip.To4(); v4 != nil {
		family = unix.AF_INET
		var addr [4]byte
		copy(addr[:], v4)
		sa = &unix.SockaddrInet4{Port: int(port), Addr: addr}
	} else {
		family = unix.AF_INET6
		var addr [16]byte
		copy(addr[:], ip.To16())
		sa = &unix.SockaddrInet6{Port: int(port), Addr: addr}
	}

	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if d, ok := ctx.Deadline(); ok {
		// Best-effort: use SO_SNDTIMEO. The real cancellation comes from
		// the caller closing the conn after a timeout.
		tv := unix.NsecToTimeval(d.Sub(time.Now()).Nanoseconds())
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	}

	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect %s:%d: %w", ip, port, err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "tcp")
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the fd; we can close ours.
	if err != nil {
		return nil, err
	}
	return conn, nil
}
