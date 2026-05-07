package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"unsafe"

	"go.uber.org/zap"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	cIFNAMSIZ   = 16
	cIFF_TUN    = 0x0001
	cIFF_NO_PI  = 0x1000
	cTUNSETIFF  = 0x400454ca
	cTUNSETPERS = 0x400454cb
)

type ifReq struct {
	Name  [cIFNAMSIZ]byte
	Flags uint16
	pad   [22]byte
}

// TUNDevice owns the file descriptor for a TUN device that we created in the
// parent namespace. The interface itself may have been moved into another
// netns; the fd remains valid for read/write.
type TUNDevice struct {
	Name string
	File *os.File
}

// CreateTUN creates a new TUN device. If name is empty, a random one is
// chosen. The returned File is a non-blocking fd suitable for use with gvisor
// fdbased.
func CreateTUN(name string) (*TUNDevice, error) {
	if name == "" {
		var b [3]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name = "mw" + hex.EncodeToString(b[:])
	}
	if len(name) >= cIFNAMSIZ {
		return nil, fmt.Errorf("tun name %q too long", name)
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = cIFF_TUN | cIFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	// trim NUL from name (kernel may have changed it for %d patterns).
	out := req.Name[:]
	for i, b := range out {
		if b == 0 {
			out = out[:i]
			break
		}
	}
	finalName := string(out)

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setnonblock: %w", err)
	}

	return &TUNDevice{
		Name: finalName,
		File: os.NewFile(uintptr(fd), "/dev/net/tun"),
	}, nil
}

// MoveToNetNS moves the link into the network namespace identified by nsFD.
// Must be called from a thread that is in the namespace where the link was
// created (the link must currently be visible).
func (t *TUNDevice) MoveToNetNS(nsFD int) error {
	link, err := netlink.LinkByName(t.Name)
	if err != nil {
		return fmt.Errorf("link by name %s: %w", t.Name, err)
	}
	if err := netlink.LinkSetNsFd(link, nsFD); err != nil {
		return fmt.Errorf("link set ns fd: %w", err)
	}
	return nil
}

// Close closes the underlying file descriptor. The TUN device disappears
// when the last fd is closed.
func (t *TUNDevice) Close() error {
	if t == nil || t.File == nil {
		return nil
	}
	err := t.File.Close()
	t.File = nil
	return err
}

func init() {
	// Helps catch broken architectures during build (struct layout assumes
	// the typical Linux 4-byte alignment).
	if unsafe.Sizeof(ifReq{}) < cIFNAMSIZ+2 {
		panic("ifreq struct layout invalid")
	}
}

// configureLinkInNS brings the TUN link up, sets address/MTU, and installs a
// default route via the device. Must run in the netns.
func configureLinkInNS(name, cidr string, mtu int, logger *zap.Logger) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link by name %s: %w", name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", cidr, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("addr replace: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up %s: %w", name, err)
	}

	// bring loopback up too.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			logger.Warn("lo up failed", zap.Error(err))
		}
	}

	// default route via the tun device. Mirror `ip route replace default dev TUN`.
	for _, dst := range []*net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	} {
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       dst,
		}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route replace default %s: %w", dst, err)
		}
	}
	logger.Info("netns link configured", zap.String("dev", name), zap.String("addr", cidr), zap.Int("mtu", mtu))
	return nil
}
