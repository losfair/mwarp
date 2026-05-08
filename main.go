package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const usage = `mwarp — single-binary SOCKS5/WireGuard + Cloudflare WARP plumbing

Usage:
  mwarp run   [flags] -- COMMAND [ARGS...]    run COMMAND through WARP
  mwarp proxy [flags]                         expose a SOCKS5 proxy whose
                                              upstream sockets dial from inside
                                              the WARP-routed egress netns

All flags can also be set via environment variables (see README/source).
When WireGuard is enabled, the private key is taken from $WG_PRIVATE_KEY only.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "proxy":
		os.Exit(cmdProxy(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdRun(args []string) int {
	cfg := &Config{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	registerCommonFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.finalize(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "run: missing command (use `--` to separate flags from command)")
		return 2
	}

	logger, err := newLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logger.Sync()

	ctx, cancel := signalContext(logger)
	defer cancel()

	state, err := setupAll(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		return 1
	}
	defer state.Close()

	exitCode, runErr := RunInNS(state.Egress, rest, logger)
	if runErr != nil {
		logger.Error("run failed", zap.Error(runErr))
		fmt.Fprintln(os.Stderr, "run:", runErr)
	}
	return exitCode
}

func cmdProxy(args []string) int {
	cfg := &Config{}
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	registerCommonFlags(fs, cfg)
	fs.StringVar(&cfg.ProxyListen, "listen", envOr("PROXY_LISTEN", "0.0.0.0:1080"), "Listen address for the SOCKS5 server in the parent ns")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := cfg.finalize(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	logger, err := newLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logger.Sync()

	ctx, cancel := signalContext(logger)
	defer cancel()

	state, err := setupAll(ctx, cfg, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup:", err)
		return 1
	}
	defer state.Close()

	if err := RunProxy(ctx, state.Egress, cfg.ProxyListen, logger); err != nil {
		logger.Error("proxy stopped", zap.Error(err))
		fmt.Fprintln(os.Stderr, "proxy:", err)
		return 1
	}
	return 0
}

func signalContext(logger *zap.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-ch
		logger.Info("signal received", zap.String("sig", s.String()))
		cancel()
		// Second signal => hard exit.
		s = <-ch
		logger.Warn("second signal, hard exit", zap.String("sig", s.String()))
		os.Exit(130)
	}()
	return ctx, cancel
}

// State bundles everything that needs cleanup on shutdown.
type State struct {
	WarpNS  *NetNS // first netns: hosts warp-svc + initial setup
	Egress  *NetNS // second netns: only egress is the warp iface; user/proxy lives here
	WG      *WGClient
	TUN     *TUNDevice
	Stack   *NSStack
	WarpSvc *exec.Cmd // killed once warp is ready and the iface is moved
	logger  *zap.Logger
}

func (s *State) Close() {
	if s.WarpSvc != nil && s.WarpSvc.Process != nil {
		_ = s.WarpSvc.Process.Signal(syscall.SIGKILL)
	}
	if s.Stack != nil {
		s.Stack.Close()
	}
	if s.TUN != nil {
		_ = s.TUN.Close()
	}
	if s.WG != nil {
		s.WG.Close()
	}
	if s.Egress != nil {
		s.Egress.Close()
	}
	if s.WarpNS != nil {
		s.WarpNS.Close()
	}
}

// setupAll wires the inner SOCKS5 path, netns, TUN, gvisor netstack, warp.
func setupAll(ctx context.Context, cfg *Config, logger *zap.Logger) (*State, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("must run as root (CAP_NET_ADMIN required)")
	}

	state := &State{logger: logger}

	var socksBase Dialer
	if cfg.NoWireGuard {
		socksBase = &net.Dialer{}
		logger.Info("wireguard disabled; using host namespace for inner socks5",
			zap.String("inner_socks5", cfg.InnerSocks5))
	} else {
		wg, err := StartWireGuard(cfg, logger)
		if err != nil {
			state.Close()
			return nil, fmt.Errorf("wireguard: %w", err)
		}
		state.WG = wg
		socksBase = wg.Net
	}

	var warpExtraBinds []BindMount
	warpCommandBinds, err := prepareWarpCommandBinds(cfg)
	if err != nil {
		state.Close()
		return nil, err
	}
	warpExtraBinds = append(warpExtraBinds, warpCommandBinds...)
	if cfg.WarpStateDir != "" {
		// Persistent registration/settings — bind only if the operator
		// asked for it. Default is ephemeral (re-registered each run).
		warpExtraBinds = append(warpExtraBinds, BindMount{
			Source: cfg.WarpStateDir,
			Target: "/var/lib/cloudflare-warp",
		})
	}
	warpNS, err := CreateNetNS(NetNSOptions{
		Nameserver: cfg.NetnsResolvNameserver,
		// warp-svc uses webpki + hardcoded fallback IPs; it doesn't
		// need /etc/ssl, /etc/passwd, or DNS-related glibc files.
		ExtraBinds: warpExtraBinds,
	}, logger)
	if err != nil {
		state.Close()
		return nil, fmt.Errorf("warp netns: %w", err)
	}
	state.WarpNS = warpNS

	tun, err := CreateTUN(cfg.TunDev)
	if err != nil {
		state.Close()
		return nil, fmt.Errorf("tun: %w", err)
	}
	state.TUN = tun
	logger.Info("tun device created", zap.String("name", tun.Name))

	if err := tun.MoveToNetNS(warpNS.NetFD); err != nil {
		state.Close()
		return nil, fmt.Errorf("tun move: %w", err)
	}

	socks := &Socks5Client{
		Server: cfg.InnerSocks5,
		Base:   socksBase,
	}
	stack, err := NewNSStack(tun.File, cfg.TunMTU, socks, logger)
	if err != nil {
		state.Close()
		return nil, fmt.Errorf("netstack: %w", err)
	}
	state.Stack = stack

	if err := warpNS.Run(func() error {
		return configureLinkInNS(tun.Name, tunAddrCIDR, cfg.TunMTU, logger)
	}); err != nil {
		state.Close()
		return nil, fmt.Errorf("configure warp netns link: %w", err)
	}

	warpSvc, err := StartWarpSvc(warpNS, cfg.WarpSvcCmd, logger)
	if err != nil {
		state.Close()
		return nil, err
	}
	if warpSvc != nil {
		state.WarpSvc = warpSvc
		go func() {
			err := warpSvc.Wait()
			logger.Warn("warp-svc exited", zap.Error(err))
		}()
	}

	// Brief head start for warp-svc to open its IPC socket; warp-cli's
	// own retry loop handles the rest.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		state.Close()
		return nil, ctx.Err()
	}

	if err := RegisterWarp(warpNS, cfg.WarpCli, cfg.WarpAcceptTOS, cfg.WarpConnectRetry, cfg.WarpConnectDelay, logger); err != nil {
		state.Close()
		return nil, err
	}

	if err := ConnectWarp(warpNS, cfg.WarpCli, cfg.WarpAcceptTOS, cfg.WarpConnectRetry, cfg.WarpConnectDelay, logger); err != nil {
		state.Close()
		return nil, err
	}

	// warp-cli connect returns once the daemon has accepted the request,
	// but the actual tunnel (and the routes that send traffic through the
	// warp iface) come up moments later. Wait for the netns route table
	// to point at the WARP device before extracting the iface — otherwise
	// the move can race the kernel's tunnel-establishing logic.
	readyTimeout := time.Duration(cfg.WarpReadyTimeout) * time.Second
	if err := WaitForWarpRoute(ctx, warpNS, cfg.WarpIface, readyTimeout, logger); err != nil {
		state.Close()
		return nil, fmt.Errorf("warp readiness: %w", err)
	}

	// Bring up a second netns whose only off-box path is back through the
	// warp netns (and from there, via warp-svc's CloudflareWARP TUN).
	// User commands run there with the host filesystem still mounted at /;
	// only /etc/resolv.conf is overlaid in the private mount namespace.
	egress, err := CreateEgressNS(warpNS, cfg.NetnsResolvNameserver, cfg.WarpIface, logger)
	if err != nil {
		state.Close()
		return nil, fmt.Errorf("egress: %w", err)
	}
	state.Egress = egress

	return state, nil
}
