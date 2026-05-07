package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID         = 1
	tcpInFlight   = 2048
	udpIdleExpiry = 60 * time.Second
)

// NSStack runs a gvisor netstack on top of the given TUN file. Inbound TCP
// connections are accepted and forwarded to dst via socks5; UDP datagrams
// likewise.
type NSStack struct {
	stack  *stack.Stack
	link   stack.LinkEndpoint
	logger *zap.Logger
	socks  *Socks5Client
	tunFD  int
}

func NewNSStack(tunFile *os.File, mtu int, socks *Socks5Client, logger *zap.Logger) (*NSStack, error) {
	// fdbased.New does NOT take ownership; tunFile must outlive this stack.
	// TUN devices don't offload checksums, so let gvisor compute them.
	link, err := fdbased.New(&fdbased.Options{
		FDs:            []int{int(tunFile.Fd())},
		MTU:            uint32(mtu),
		EthernetHeader: false,
	})
	if err != nil {
		return nil, fmt.Errorf("fdbased.New: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	})

	if e := s.CreateNIC(nicID, link); e != nil {
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}
	// Accept any destination IP so we can intercept all traffic.
	s.SetSpoofing(nicID, true)
	s.SetPromiscuousMode(nicID, true)
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	sackOpt := tcpip.TCPSACKEnabled(true)
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); e != nil {
		return nil, fmt.Errorf("set TCPSACK: %v", e)
	}

	ns := &NSStack{
		stack:  s,
		link:   link,
		logger: logger,
		socks:  socks,
		tunFD:  int(tunFile.Fd()),
	}

	tcpFwd := tcp.NewForwarder(s, 0, tcpInFlight, ns.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, ns.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	logger.Info("netstack up", zap.Int("mtu", mtu))
	return ns, nil
}

func (n *NSStack) Close() {
	if n.stack != nil {
		n.stack.Close()
		n.stack = nil
	}
}

func (n *NSStack) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dst := tcpipFullAddr(id.LocalAddress, id.LocalPort)
	src := tcpipFullAddr(id.RemoteAddress, id.RemotePort)

	wq := &waiter.Queue{}
	ep, err := req.CreateEndpoint(wq)
	if err != nil {
		n.logger.Debug("tcp accept failed",
			zap.String("src", src),
			zap.String("dst", dst),
			zap.String("err", err.String()))
		req.Complete(true)
		return
	}
	req.Complete(false)

	local := gonet.NewTCPConn(wq, ep)

	go func() {
		defer local.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		remote, dialErr := n.socks.DialContext(ctx, "tcp", dst)
		cancel()
		if dialErr != nil {
			n.logger.Debug("tcp dial failed",
				zap.String("dst", dst),
				zap.Error(dialErr))
			return
		}
		defer remote.Close()
		n.logger.Debug("tcp open", zap.String("src", src), zap.String("dst", dst))
		pipe(local, remote)
		n.logger.Debug("tcp closed", zap.String("src", src), zap.String("dst", dst))
	}()
}

func tcpipFullAddr(a tcpip.Address, p uint16) string {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(p), 10))
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (n *NSStack) handleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	dst := tcpipFullAddr(id.LocalAddress, id.LocalPort)
	src := tcpipFullAddr(id.RemoteAddress, id.RemotePort)

	wq := &waiter.Queue{}
	ep, err := req.CreateEndpoint(wq)
	if err != nil {
		n.logger.Debug("udp accept failed",
			zap.String("src", src),
			zap.String("dst", dst),
			zap.String("err", err.String()))
		return
	}
	local := gonet.NewUDPConn(wq, ep)

	dstHost, dstPortStr, splitErr := net.SplitHostPort(dst)
	if splitErr != nil {
		n.logger.Debug("udp parse dst failed", zap.String("dst", dst))
		local.Close()
		return
	}
	dstAddr, parseErr := netip.ParseAddr(dstHost)
	if parseErr != nil {
		local.Close()
		return
	}
	dstPort, _ := strconv.ParseUint(dstPortStr, 10, 16)
	dstAP := netip.AddrPortFrom(dstAddr, uint16(dstPort))

	go func() {
		defer local.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		sess, err := n.socks.UDPAssociate(ctx)
		cancel()
		if err != nil {
			n.logger.Debug("udp associate failed", zap.Error(err))
			return
		}
		defer sess.Close()
		n.logger.Debug("udp open", zap.String("src", src), zap.String("dst", dst))
		udpPipe(local, sess, dstAP, n.logger)
		n.logger.Debug("udp closed", zap.String("src", src), zap.String("dst", dst))
	}()
}

func udpPipe(local *gonet.UDPConn, remote *Socks5UDPSession, dstAP netip.AddrPort, logger *zap.Logger) {
	doneCh := make(chan struct{}, 2)
	// local -> remote
	go func() {
		buf := make([]byte, 65535)
		for {
			local.SetReadDeadline(time.Now().Add(udpIdleExpiry))
			n, _, err := local.ReadFrom(buf)
			if err != nil {
				doneCh <- struct{}{}
				return
			}
			if _, err := remote.WriteTo(buf[:n], dstAP); err != nil {
				doneCh <- struct{}{}
				return
			}
		}
	}()
	// remote -> local
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := remote.ReadFrom(buf)
			if err != nil {
				doneCh <- struct{}{}
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				doneCh <- struct{}{}
				return
			}
		}
	}()
	<-doneCh
}

var errCancelled = errors.New("cancelled")

