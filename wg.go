package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WGClient struct {
	Net    *netstack.Net
	device *device.Device
	logger *zap.Logger
}

func decodeKey(k string) (string, error) {
	k = strings.TrimSpace(k)
	if k == "" {
		return "", fmt.Errorf("empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return "", fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// resolveEndpoint resolves a host:port endpoint via the system resolver
// (since this dial happens before the WG tunnel is up).
func resolveEndpoint(ep string) (string, error) {
	if _, err := validateEndpoint(ep); err != nil {
		return "", err
	}
	host, port, _ := net.SplitHostPort(ep)
	if ip := net.ParseIP(host); ip != nil {
		return ep, nil
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

func validateEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", ep, err)
	}
	if host == "" {
		return "", fmt.Errorf("invalid endpoint %q: missing host", ep)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("invalid endpoint %q: invalid port %q: %w", ep, port, err)
	}
	return ep, nil
}

func StartWireGuard(c *Config, logger *zap.Logger) (*WGClient, error) {
	dnsServers := []netip.Addr{netip.MustParseAddr(c.NetnsResolvNameserver)}
	tun, tnet, err := netstack.CreateNetTUN(c.WGAddress, dnsServers, c.WGMTU)
	if err != nil {
		return nil, fmt.Errorf("create wg netstack: %w", err)
	}

	priv, err := decodeKey(c.WGPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: %w", err)
	}
	pub, err := decodeKey(c.WGPublicKey)
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}

	var endpoint string
	if c.OuterSocks5 != "" {
		endpoint, err = validateEndpoint(c.WGEndpoint)
	} else if c.WGOverTCP {
		endpoint, err = resolveTCPEndpoint(c.WGEndpoint)
	} else {
		endpoint, err = resolveEndpoint(c.WGEndpoint)
	}
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", priv)
	fmt.Fprintf(&sb, "public_key=%s\n", pub)
	if c.WGPresharedKey != "" {
		psk, err := decodeKey(c.WGPresharedKey)
		if err != nil {
			return nil, fmt.Errorf("preshared_key: %w", err)
		}
		fmt.Fprintf(&sb, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&sb, "endpoint=%s\n", endpoint)
	if c.WGPersistentKA > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", c.WGPersistentKA)
	}
	for _, p := range c.WGAllowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", p.String())
	}

	dlogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...))
		},
	}

	var bind conn.Bind
	if c.WGOverTCP {
		if c.OuterSocks5 != "" {
			bind = NewTCPBindWithDialer(endpoint, newOuterSocks5Client(c.OuterSocks5))
		} else {
			bind = NewTCPBind(endpoint)
		}
	} else if c.OuterSocks5 != "" {
		bind = NewSocks5Bind(newOuterSocks5Client(c.OuterSocks5))
	} else {
		bind = conn.NewDefaultBind()
	}

	dev := device.NewDevice(tun, bind, dlogger)
	if err := dev.IpcSet(sb.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg up: %w", err)
	}

	transport := "udp"
	if c.WGOverTCP {
		transport = "tcp (udp2tcp)"
	}
	if c.OuterSocks5 != "" {
		transport += " over socks5"
	}
	logger.Info("wireguard up",
		zap.String("endpoint", endpoint),
		zap.String("transport", transport),
		zap.String("outer_socks5", c.OuterSocks5),
		zap.Any("addresses", c.WGAddress),
		zap.Int("mtu", c.WGMTU),
	)

	return &WGClient{Net: tnet, device: dev, logger: logger}, nil
}

func (w *WGClient) Close() {
	if w.device != nil {
		w.device.Close()
	}
}
