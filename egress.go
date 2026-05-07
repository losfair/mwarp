package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// Veth IP scheme: a /30 in the link-local 169.254/16 range, picked so it's
// extremely unlikely to collide with anything the operator has on their host
// (warp's assigned subnet, mullvad's, the configured TUN, etc.).
const (
	egressVethWarp = "mw-warp"   // warp-side veth name (lives in warp netns)
	egressVethEdge = "mw-egress" // egress-side veth name (lives in egress netns)

	egressWarpAddr = "169.254.42.1/30"
	egressEdgeAddr = "169.254.42.2/30"
	egressEdgeGW   = "169.254.42.1"
)

// CreateEgressNS spins up the second namespace described in the README.
// warp-svc and the warp iface stay in the warp netns; we just bridge the two
// namespaces with a veth pair and route everything in the egress netns
// through it. From the egress netns's perspective, the only off-box path is
// "default via the warp netns" — and the warp netns hands any forwarded
// traffic to the CloudflareWARP TUN per warp-svc's policy routing.
//
// One small nftables hook in the warp netns: MASQUERADE on packets going out
// CloudflareWARP. warp-svc's own filter chain only accepts plaintext from
// 172.16.0.2 (the warp-assigned IP) so without SNAT, forwarded traffic with
// veth source IPs would be rejected. With masquerade, the kernel rewrites
// src to CloudflareWARP's own address before warp-svc reads the packet.
func CreateEgressNS(warpNS *NetNS, resolvNameserver, warpIface string, logger *zap.Logger) (*NetNS, error) {
	egress, err := CreateNetNS(NetNSOptions{
		Nameserver: resolvNameserver,
		// User-facing programs (curl, bash, dig, ...) need glibc's
		// resolver config and the system CA bundle.
		ExtraEtcBinds: []string{
			"ssl",
			"hosts",
			"passwd",
			"group",
			"nsswitch.conf",
			"protocols",
			"services",
			"ca-certificates",
			"ca-certificates.conf",
		},
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("create egress netns: %w", err)
	}

	// Veth creation runs in the warp netns: that's where the new pair is
	// born; we then move one end into the egress netns.
	err = warpNS.Run(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: egressVethWarp,
				MTU:  1420,
			},
			PeerName: egressVethEdge,
		}
		// idempotent-ish: if a stale veth from a crashed run is still
		// around, drop it so LinkAdd doesn't fail.
		if old, err := netlink.LinkByName(egressVethWarp); err == nil {
			_ = netlink.LinkDel(old)
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("veth add: %w", err)
		}

		peer, err := netlink.LinkByName(egressVethEdge)
		if err != nil {
			return fmt.Errorf("locate peer: %w", err)
		}
		if err := netlink.LinkSetNsFd(peer, egress.NetFD); err != nil {
			return fmt.Errorf("move peer to egress: %w", err)
		}

		warpSide, err := netlink.LinkByName(egressVethWarp)
		if err != nil {
			return fmt.Errorf("locate warp-side: %w", err)
		}
		addr, err := netlink.ParseAddr(egressWarpAddr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(warpSide, addr); err != nil {
			return fmt.Errorf("addr add warp-side: %w", err)
		}
		if err := netlink.LinkSetUp(warpSide); err != nil {
			return fmt.Errorf("warp-side up: %w", err)
		}

		// Enable forwarding *in the warp netns*. Sysctl writes are
		// scoped to the current netns so this doesn't touch the host.
		if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
			return fmt.Errorf("ip_forward: %w", err)
		}
		// rp_filter would drop forwarded packets whose reverse path
		// doesn't match (the egress IP is reachable only via veth, not
		// via CloudflareWARP) — relax it to "loose mode" so the kernel
		// allows asymmetric paths between veth and CloudflareWARP.
		if err := writeSysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "2"); err != nil {
			logger.Debug("rp_filter relax failed", zap.Error(err))
		}
		if err := writeSysctl("/proc/sys/net/ipv4/conf/"+egressVethWarp+"/rp_filter", "2"); err != nil {
			logger.Debug("rp_filter relax (veth) failed", zap.Error(err))
		}
		return nil
	})
	if err != nil {
		egress.Close()
		return nil, err
	}

	// MASQUERADE forwarded traffic on its way out CloudflareWARP, so its
	// source becomes the warp-assigned IP (warp-svc's own output filter
	// only accepts plaintext from that IP).
	if err := warpNS.Run(func() error { return installMasquerade(warpIface) }); err != nil {
		egress.Close()
		return nil, fmt.Errorf("masquerade: %w", err)
	}

	// Configure the egress side: address, link up, default route through
	// the warp side of the veth.
	err = egress.Run(func() error {
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetUp(lo)
		}
		link, err := netlink.LinkByName(egressVethEdge)
		if err != nil {
			return fmt.Errorf("egress: locate veth: %w", err)
		}
		addr, err := netlink.ParseAddr(egressEdgeAddr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("egress: addr add: %w", err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("egress: link up: %w", err)
		}
		gw := net.ParseIP(egressEdgeGW)
		defaultRoute := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        gw,
		}
		if err := netlink.RouteReplace(defaultRoute); err != nil {
			return fmt.Errorf("egress: default route: %w", err)
		}
		return nil
	})
	if err != nil {
		egress.Close()
		return nil, err
	}

	logger.Info("egress netns ready",
		zap.String("warp_veth", egressVethWarp),
		zap.String("edge_veth", egressVethEdge),
		zap.String("default_gw", egressEdgeGW))

	return egress, nil
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}

// installMasquerade sets up the single-rule nat table that lets forwarded
// traffic out via CloudflareWARP get its source rewritten to the warp iface's
// IP. Must run inside the warp netns.
func installMasquerade(warpIface string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables.New: %w", err)
	}
	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "mwarp_egress",
	})
	c.FlushTable(table)
	chain := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(warpIface)},
			&expr.Masq{},
		},
	})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft flush: %w", err)
	}
	return nil
}

// ifname pads an interface name to IFNAMSIZ for OIFNAME comparisons.
func ifname(s string) []byte {
	const sz = 16
	b := make([]byte, sz)
	copy(b, s)
	return b
}
