package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	NoWireGuard    bool
	WGEndpoint     string
	WGPublicKey    string
	WGPresharedKey string
	WGPrivateKey   string
	WGAddress      []netip.Addr
	WGAllowedIPs   []netip.Prefix
	WGMTU          int
	WGPersistentKA int
	WGOverTCP      bool
	OuterSocks5    string

	InnerSocks5 string

	TunDev string
	TunMTU int

	NetnsResolvNameserver string

	WarpSvcCmd       string
	WarpCli          string
	WarpAcceptTOS    bool
	WarpConnectRetry int
	WarpConnectDelay int
	WarpReadyTimeout int
	WarpIface        string
	WarpStateDir     string

	LogFile string

	ProxyListen string

	wgAddrRaw    string
	wgAllowedRaw string
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func parseAddrList(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid wg-address %q: %w", raw, err)
			}
			out = append(out, p.Addr())
		} else {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid wg-address %q: %w", raw, err)
			}
			out = append(out, a)
		}
	}
	return out, nil
}

func parsePrefixList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed-ip %q: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func registerCommonFlags(fs *flag.FlagSet, c *Config) {
	fs.BoolVar(&c.NoWireGuard, "no-wireguard", envBool("NO_WIREGUARD", false), "Skip userspace WireGuard and reach --inner-socks5 directly from the host namespace")

	fs.StringVar(&c.WGEndpoint, "wg-endpoint", envOr("WG_ENDPOINT", ""), "WireGuard peer endpoint host:port")
	fs.StringVar(&c.WGPublicKey, "wg-public-key", envOr("WG_PUBLIC_KEY", ""), "WireGuard peer public key (base64)")
	fs.StringVar(&c.WGPresharedKey, "wg-preshared-key", envOr("WG_PRESHARED_KEY", ""), "WireGuard preshared key (optional, base64)")
	fs.StringVar(&c.InnerSocks5, "inner-socks5", envOr("INNER_SOCKS5", ""), "Inner SOCKS5 server reachable inside the WG tunnel (host:port)")
	fs.StringVar(&c.OuterSocks5, "outer-socks5", envOr("OUTER_SOCKS5", ""), "Outer SOCKS5 server used to reach the WG endpoint before the tunnel is up (host:port)")

	fs.StringVar(&c.wgAddrRaw, "wg-address", envOr("WG_ADDRESS", ""), "Comma-separated WireGuard local addresses (CIDR or bare addr)")
	fs.StringVar(&c.wgAllowedRaw, "wg-allowed-ips", envOr("WG_ALLOWED_IPS", "0.0.0.0/0,::/0"), "Comma-separated peer allowed-IPs CIDRs")

	fs.IntVar(&c.WGMTU, "wg-mtu", envInt("WG_MTU", 1280), "WireGuard MTU")
	fs.IntVar(&c.WGPersistentKA, "wg-persistent-keepalive", envInt("WG_PERSISTENT_KEEPALIVE", 25), "WireGuard persistent keepalive (seconds)")
	fs.BoolVar(&c.WGOverTCP, "wg-over-tcp", envBool("WG_OVER_TCP", false), "Tunnel WG datagrams to the endpoint over TCP using udp2tcp framing (16-bit BE length prefix)")

	fs.StringVar(&c.TunDev, "tun-dev", envOr("TUN_DEV", ""), "Kernel TUN device name (random if empty)")
	fs.IntVar(&c.TunMTU, "tun-mtu", envInt("TUN_MTU", 1420), "TUN MTU")

	fs.StringVar(&c.NetnsResolvNameserver, "resolv-nameserver", envOr("RESOLV_NAMESERVER", "8.8.8.8"), "Nameserver for /etc/resolv.conf inside netns")

	fs.StringVar(&c.WarpSvcCmd, "warp-svc-cmd", envOr("WARP_SVC_CMD", "warp-svc"), "warp-svc command (empty to skip)")
	fs.StringVar(&c.WarpCli, "warp-cli", envOr("WARP_CLI", "warp-cli"), "warp-cli command (empty to skip connect)")
	fs.BoolVar(&c.WarpAcceptTOS, "warp-accept-tos", envBool("WARP_ACCEPT_TOS", true), "Pass --accept-tos to warp-cli")
	fs.IntVar(&c.WarpConnectRetry, "warp-connect-retries", envInt("WARP_CONNECT_RETRIES", 5), "warp-cli connect retries")
	fs.IntVar(&c.WarpConnectDelay, "warp-connect-delay", envInt("WARP_CONNECT_DELAY", 2), "warp-cli connect delay (seconds)")
	fs.IntVar(&c.WarpReadyTimeout, "warp-ready-timeout", envInt("WARP_READY_TIMEOUT", 60), "Seconds to wait for the netns default route to land on the WARP iface (after warp-cli connect)")
	fs.StringVar(&c.WarpIface, "warp-iface", envOr("WARP_IFACE", "CloudflareWARP"), "Name of the kernel WireGuard interface created by warp-svc")
	fs.StringVar(&c.WarpStateDir, "warp-state-dir", envOr("WARP_STATE_DIR", ""), "If set, bind-mount this host path into the warp sandbox at /var/lib/cloudflare-warp so warp-svc state persists across runs. Empty (default) = ephemeral: a fresh device is registered on every start")

	fs.StringVar(&c.LogFile, "log-file", envOr("LOG_FILE", ""), "Path to JSON log file (default: blackhole)")
}

func (c *Config) finalize() error {
	var err error
	if c.InnerSocks5 == "" {
		return fmt.Errorf("--inner-socks5 / INNER_SOCKS5 is required")
	}
	if _, _, err := net.SplitHostPort(c.InnerSocks5); err != nil {
		return fmt.Errorf("invalid inner socks5 address %q: %w", c.InnerSocks5, err)
	}
	if c.NoWireGuard {
		return nil
	}
	if c.WGAddress, err = parseAddrList(c.wgAddrRaw); err != nil {
		return err
	}
	if c.WGAllowedIPs, err = parsePrefixList(c.wgAllowedRaw); err != nil {
		return err
	}
	c.WGPrivateKey = os.Getenv("WG_PRIVATE_KEY")
	if c.WGPrivateKey == "" {
		return fmt.Errorf("WG_PRIVATE_KEY env var is required")
	}
	if c.WGEndpoint == "" {
		return fmt.Errorf("--wg-endpoint / WG_ENDPOINT is required")
	}
	if c.WGPublicKey == "" {
		return fmt.Errorf("--wg-public-key / WG_PUBLIC_KEY is required")
	}
	if err := validateOuterSocks5(c.OuterSocks5); err != nil {
		return err
	}
	if len(c.WGAddress) == 0 {
		return fmt.Errorf("--wg-address / WG_ADDRESS is required (e.g. 10.66.123.45/32)")
	}
	if len(c.WGAllowedIPs) == 0 {
		c.WGAllowedIPs = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	return nil
}
