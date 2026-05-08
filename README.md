# mwarp

`mwarp` is a Linux-only helper that runs Cloudflare WARP behind an inner
SOCKS5 path, optionally reached through userspace WireGuard, then runs a
command or exposes a SOCKS5 proxy whose traffic exits through WARP.

The important property is the traffic shape:

```text
user command / parent SOCKS5 listener
  -> egress network namespace
  -> CloudflareWARP interface in WARP namespace
  -> warp-svc traffic
  -> kernel TUN handled by gVisor netstack
  -> inner SOCKS5 server
  -> userspace WireGuard tunnel (unless --no-wireguard)
  -> WireGuard peer
```

The WARP daemon's own network traffic is forced through the inner SOCKS5
server. By default that server is reached over userspace WireGuard; with
`--no-wireguard`, it is dialed directly from the host namespace. User traffic is
placed in a second namespace whose only default route points back through the
WARP namespace.

## What It Does

- Starts a userspace WireGuard device with `wireguard-go`'s netstack TUN unless
  `--no-wireguard` is set. There is no `wg-quick` dependency and no kernel
  WireGuard interface for the inner tunnel.
- Optionally reaches the WireGuard peer through an outer no-auth SOCKS5 proxy.
  UDP WireGuard uses SOCKS5 `UDP ASSOCIATE`; `--wg-over-tcp` uses a
  Mullvad-compatible 16-bit big-endian udp-over-tcp frame stream, optionally
  through the same outer SOCKS5 proxy.
- Creates a sandboxed WARP namespace with a minimal tmpfs root. It bind-mounts
  only the resolved `warp-svc` and `warp-cli` executables, `/usr`, `/sys`,
  `/proc`, minimal `/dev` nodes, generated DNS config, and optional WARP state.
- Creates a kernel TUN device in the WARP namespace and attaches it to a
  gVisor netstack in the parent process. The netstack accepts TCP and UDP flows
  from WARP and forwards them through the inner SOCKS5 server, either over
  WireGuard or directly from the host namespace.
- Starts `warp-svc`, registers WARP with `warp-cli registration new`, runs
  `warp-cli connect`, and waits until the default route for `1.1.1.1` uses the
  configured WARP interface.
- Creates a second egress namespace with the host filesystem still mounted at
  `/`, except for a namespace-local read-only `/etc/resolv.conf`.
- Connects the WARP and egress namespaces with a veth pair. The egress
  namespace gets IPv4 and IPv6 default routes through that pair.
- Installs nftables rules inside the WARP namespace to drop forwarded egress
  traffic unless it leaves via the WARP interface, and to masquerade forwarded
  IPv4/IPv6 traffic going out through WARP.
- Implements a parent-namespace no-auth SOCKS5 server in `proxy` mode. Accepted
  TCP connections are dialed from inside the egress namespace, so proxy
  upstream traffic follows the WARP route.

All namespace work is done with netlink, nftables netlink, `setns`, and
thread-pinned goroutines. `mwarp` does not shell out to `ip`, `nsenter`, or
`nft`; the external runtime dependency is Cloudflare WARP itself
(`warp-svc` and `warp-cli`).

## Subcommands

```sh
mwarp run   [flags] -- COMMAND [ARGS...]
mwarp proxy [flags]
```

`run` creates the namespaces, brings up WireGuard and WARP, then executes the
command inside the egress namespace. It attaches the current stdio and returns
the child process exit code.

`proxy` creates the same plumbing, then listens for SOCKS5 clients in the
parent namespace. Only no-auth SOCKS5 `CONNECT` is supported by the listener.
Upstream sockets are opened from inside the egress namespace.

## Configuration

All flags can also be supplied as environment variables. When WireGuard is
enabled, `WG_PRIVATE_KEY` is environment-only and is required.

| Flag | Env | Default | Notes |
| ---- | --- | ------- | ----- |
| `--no-wireguard` | `NO_WIREGUARD` | `false` | Skip userspace WireGuard and dial `--inner-socks5` directly from the host namespace. |
| `--wg-endpoint` | `WG_ENDPOINT` | required with WireGuard | WireGuard peer endpoint as `host:port`. Ignored with `--no-wireguard`. |
| `--wg-public-key` | `WG_PUBLIC_KEY` | required with WireGuard | WireGuard peer public key, base64. Ignored with `--no-wireguard`. |
| `--wg-preshared-key` | `WG_PRESHARED_KEY` | empty | Optional preshared key, base64. |
| `--wg-address` | `WG_ADDRESS` | required with WireGuard | Comma-separated local WireGuard addresses. CIDR and bare IP forms are accepted. Ignored with `--no-wireguard`. |
| `--wg-allowed-ips` | `WG_ALLOWED_IPS` | `0.0.0.0/0,::/0` | Comma-separated peer allowed-IP CIDRs. |
| `--wg-mtu` | `WG_MTU` | `1280` | Userspace WireGuard MTU. |
| `--wg-persistent-keepalive` | `WG_PERSISTENT_KEEPALIVE` | `25` | WireGuard persistent keepalive in seconds; `0` disables it. |
| `--wg-over-tcp` | `WG_OVER_TCP` | `false` | Send WireGuard datagrams over one TCP connection using udp-over-tcp framing. |
| `--outer-socks5` | `OUTER_SOCKS5` | empty | Optional no-auth SOCKS5 server used to reach the WireGuard endpoint before the tunnel is up. Ignored with `--no-wireguard`. |
| `--inner-socks5` | `INNER_SOCKS5` | required | No-auth SOCKS5 server used for WARP daemon egress. It must be reachable inside WireGuard by default, or directly from the host namespace with `--no-wireguard`. |
| `--tun-dev` | `TUN_DEV` | random `mwxxxxxx` | Kernel TUN device name created for the WARP namespace. |
| `--tun-mtu` | `TUN_MTU` | `1420` | MTU for the WARP-facing TUN and gVisor netstack. |
| `--resolv-nameserver` | `RESOLV_NAMESERVER` | `8.8.8.8` | Nameserver written to namespace-local `resolv.conf` files and used by the WireGuard netstack. |
| `--warp-svc-cmd` | `WARP_SVC_CMD` | `warp-svc` | Command used to start WARP service. May include arguments. Empty disables starting it. |
| `--warp-cli` | `WARP_CLI` | `warp-cli` | Command used for registration/connect. Empty skips CLI calls, but WARP routing must still become ready before timeout. |
| `--warp-accept-tos` | `WARP_ACCEPT_TOS` | `true` | Pass `--accept-tos` to `warp-cli`; connect retries without it if the installed CLI rejects the flag. |
| `--warp-connect-retries` | `WARP_CONNECT_RETRIES` | `5` | Registration/connect retry attempts. |
| `--warp-connect-delay` | `WARP_CONNECT_DELAY` | `2` | Delay between registration/connect attempts, in seconds. |
| `--warp-ready-timeout` | `WARP_READY_TIMEOUT` | `60` | Seconds to wait for the WARP namespace route to use `--warp-iface`. |
| `--warp-iface` | `WARP_IFACE` | `CloudflareWARP` | Interface name created by `warp-svc`. Also used by the nftables forward guard and masquerade rules. |
| `--warp-state-dir` | `WARP_STATE_DIR` | empty | Host directory bind-mounted at `/var/lib/cloudflare-warp` in the WARP sandbox. Empty means ephemeral WARP state and a fresh registration each run. |
| `--log-file` | `LOG_FILE` | empty | Append JSON logs here. Empty disables logging. |
| `--listen` | `PROXY_LISTEN` | `127.0.0.1:1080` | `proxy` only. Parent-namespace SOCKS5 listen address. The listener is no-auth SOCKS5; bind to `0.0.0.0` only on a trusted network. |

Boolean environment values accept `1/0`, `true/false`, `yes/no`, and `on/off`.
Invalid integer or boolean environment values fall back to the default.

## Examples

Run a command through WARP:

```sh
sudo WG_PRIVATE_KEY='...' \
  mwarp run \
  --wg-endpoint 'example.com:51820' \
  --wg-public-key '...' \
  --wg-address '10.66.0.2/32,fd00::2/128' \
  --inner-socks5 '10.66.0.1:1080' \
  --warp-state-dir /var/lib/mwarp-cloudflare-warp \
  -- curl https://cloudflare.com/cdn-cgi/trace
```

Expose a SOCKS5 proxy whose upstream traffic exits through WARP:

```sh
sudo WG_PRIVATE_KEY='...' \
  mwarp proxy \
  --wg-endpoint 'example.com:51820' \
  --wg-public-key '...' \
  --wg-address '10.66.0.2/32' \
  --inner-socks5 '10.66.0.1:1080' \
  --listen '127.0.0.1:1080'
```

Tunnel the inner WireGuard datagrams over TCP:

```sh
sudo WG_PRIVATE_KEY='...' \
  mwarp run \
  --wg-over-tcp \
  --wg-endpoint 'example.com:443' \
  --wg-public-key '...' \
  --wg-address '10.66.0.2/32' \
  --inner-socks5 '10.66.0.1:1080' \
  -- curl https://cloudflare.com/cdn-cgi/trace
```

Run without userspace WireGuard, dialing the inner SOCKS5 server directly from
the host namespace:

```sh
sudo mwarp run \
  --no-wireguard \
  --inner-socks5 '127.0.0.1:1080' \
  -- curl https://cloudflare.com/cdn-cgi/trace
```

## Build

```sh
go build -o mwarp .
```

The module currently targets Go 1.25.5.

## Requirements And Notes

- Linux only.
- Run as root. The process creates network and mount namespaces, TUN devices,
  veth pairs, routes, nftables tables, bind mounts, and minimal device nodes.
- `/dev/net/tun` must be available.
- `warp-svc` and `warp-cli` must be installed and discoverable on `PATH`, or
  configured with `--warp-svc-cmd` and `--warp-cli`.
- The inner and outer SOCKS5 clients implemented by `mwarp` support no-auth
  SOCKS5 only.
- By default WARP state is ephemeral. Set `--warp-state-dir` if you want
  Cloudflare WARP registration and settings to persist across runs.
