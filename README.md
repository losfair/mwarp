# mwarp

Single Linux binary that stacks Cloudflare WARP on top of an upstream
WireGuard + SOCKS5 path, so traffic exits via WARP while the WARP daemon's own
egress is forced through the WireGuard tunnel.

What it does:

- speaks **userspace WireGuard** (no `wg-quick`, no kernel module) to the
  configured peer, exposing a netstack-backed dialer that can reach the
  upstream **SOCKS5** server inside the tunnel. WG packets can optionally be
  tunnelled over TCP using Mullvad-compatible `udp2tcp` framing for networks
  that block UDP;
- creates a **fresh network namespace** anchored to a long-lived OS thread
  (with a private mount namespace and a synthetic `/etc/resolv.conf`);
- creates a **kernel TUN device**, hands the file descriptor to a
  **gVisor netstack** that terminates TCP/UDP, and moves the link into the
  netns where it is the default route;
- forwards every accepted TCP/UDP flow on the netstack through the configured
  SOCKS5 server, dialing via WireGuard;
- runs **`warp-svc` and `warp-cli`** as subprocesses inside the netns, so all
  WARP egress lands on the TUN and is funneled out via SOCKS5+WG;
- installs **nftables** rules (via netlink) inside the netns that drop any
  packet marked with `fwmark=1` unless it egresses via the `CloudflareWARP`
  device — this is the lock that keeps the `proxy` mode honest.

All netns operations use thread-pinned goroutines (`runtime.LockOSThread` +
`unix.Setns`), not `ip` / `nsenter` / `nft` subprocesses. The only external
binary dependency is Cloudflare WARP itself (`warp-svc`, `warp-cli`).

## Subcommands

```
mwarp run   [flags] -- COMMAND [ARGS...]    run COMMAND inside the WARP netns
mwarp proxy [flags]                         expose a SOCKS5 proxy whose
                                            upstream sockets dial from inside
                                            the WARP netns
```

## Configuration

All flags can also be supplied as environment variables. The WireGuard
**private key** is taken from `$WG_PRIVATE_KEY` only — never as a flag.

| Flag | Env | Default | Notes |
| ---- | --- | ------- | ----- |
| `--wg-endpoint` | `WG_ENDPOINT` | _required_ | `host:port` |
| `--wg-public-key` | `WG_PUBLIC_KEY` | _required_ | base64 |
| `--wg-preshared-key` | `WG_PRESHARED_KEY` |  | base64, optional |
| `--wg-address` | `WG_ADDRESS` | _required_ | comma-separated IPs/CIDRs |
| `--wg-allowed-ips` | `WG_ALLOWED_IPS` | `0.0.0.0/0,::/0` | comma-separated CIDRs |
| `--wg-mtu` | `WG_MTU` | `1280` |  |
| `--wg-persistent-keepalive` | `WG_PERSISTENT_KEEPALIVE` | `25` |  |
| `--wg-over-tcp` | `WG_OVER_TCP` | `false` | tunnel WG datagrams over TCP using udp2tcp framing |
| `--upstream-socks5` | `UPSTREAM_SOCKS5` | _required_ | SOCKS5 server reachable inside the WG tunnel |
| `--tun-dev` | `TUN_DEV` | random | inside-netns TUN name |
| `--tun-addr` | `TUN_ADDR` | `198.18.0.1/15` |  |
| `--tun-mtu` | `TUN_MTU` | `1420` |  |
| `--resolv-nameserver` | `RESOLV_NAMESERVER` | `8.8.8.8` |  |
| `--warp-svc-cmd` | `WARP_SVC_CMD` | `warp-svc` | empty = skip |
| `--warp-cli` | `WARP_CLI` | `warp-cli` | empty = skip connect |
| `--warp-accept-tos` | `WARP_ACCEPT_TOS` | `true` |  |
| `--warp-connect-retries` | `WARP_CONNECT_RETRIES` | `5` |  |
| `--warp-connect-delay` | `WARP_CONNECT_DELAY` | `2` | seconds |
| `--warp-ready-timeout` | `WARP_READY_TIMEOUT` | `60` | seconds to wait for the netns default route to land on the WARP iface (`warp-cli connect` reports success before the tunnel is actually up) |
| `--warp-iface` | `WARP_IFACE` | `CloudflareWARP` | warp-svc's interface name |
| `--warp-state-dir` | `WARP_STATE_DIR` | _empty_ | if set, bind-mount this host dir into the sandbox at `/var/lib/cloudflare-warp` so registration persists; default is ephemeral (`warp-cli registration new` on every run) |
| `--nft-fwmark` | `NFT_FWMARK` | `1` |  |
| `--nft-iface` | `NFT_IFACE` | `CloudflareWARP` |  |
| `--log-file` | `LOG_FILE` | _empty_ | JSON log file; empty = blackhole |
| `--listen` (proxy only) | `PROXY_LISTEN` | `0.0.0.0:1080` | parent-ns SOCKS5 listener |

## Build

```sh
go build -o mwarp .
```

Requires Linux. Run as root (CAP_NET_ADMIN, CAP_SYS_ADMIN).
