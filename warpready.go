package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// WaitForWarpRoute polls the netns routing table until traffic to the
// internet (probed via 1.1.1.1) resolves to the WARP device. This is the
// real readiness signal: warp-cli reports "Connected" before warp-svc has
// installed its routes, and the nft escape rules drop any marked traffic
// that doesn't egress via the WARP iface — so without this wait, the proxy
// or user command can race the route table and see drops on the first few
// connections.
func WaitForWarpRoute(ctx context.Context, ns *NetNS, expectedIface string, timeout time.Duration, logger *zap.Logger) error {
	deadline := time.Now().Add(timeout)
	probe := net.ParseIP("1.1.1.1")
	pollEvery := 250 * time.Millisecond
	var lastIface string
	var lastErr error

	for {
		var iface string
		err := ns.Run(func() error {
			routes, err := netlink.RouteGet(probe)
			if err != nil {
				return err
			}
			if len(routes) == 0 {
				return fmt.Errorf("no route to %s", probe)
			}
			link, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err != nil {
				return fmt.Errorf("link by index %d: %w", routes[0].LinkIndex, err)
			}
			iface = link.Attrs().Name
			return nil
		})
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			if iface != lastIface {
				logger.Debug("warp readiness probe",
					zap.String("via", iface),
					zap.String("expected", expectedIface))
				lastIface = iface
			}
			if iface == expectedIface {
				logger.Info("warp route ready", zap.String("iface", iface))
				return nil
			}
		}

		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollEvery):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("warp not ready after %s: %w", timeout, lastErr)
	}
	return fmt.Errorf("warp not ready after %s: route still via %q (expected %q)",
		timeout, lastIface, expectedIface)
}
