package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// NetNS owns a long-lived OS thread that lives inside a fresh network and
// mount namespace. The net/mnt namespace fds are exposed so other threads (or
// child processes) can join the namespaces via setns.
type NetNS struct {
	NetFD int
	MntFD int

	logger *zap.Logger

	stagingDir string // host-side scratch dir for sandbox tmpfs or resolv overlay

	taskCh chan func()
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NetNSRootMode describes the mount namespace root made visible to processes
// spawned inside a NetNS.
type NetNSRootMode int

const (
	// NetNSRootSandbox pivots the namespace into a synthetic tmpfs root.
	NetNSRootSandbox NetNSRootMode = iota
	// NetNSRootHost keeps the host filesystem mounted at / and only overlays
	// the namespace-local /etc/resolv.conf.
	NetNSRootHost
)

// NetNSOptions describes how to populate the root visible inside the netns.
// By default, the anchor pivots into a fresh tmpfs containing only:
//
//   - read-only bind mounts of host /usr, /sys, plus a fresh procfs;
//   - minimal /dev character devices needed by warp;
//   - top-level symlinks /bin /sbin /lib /lib64 → /usr/...;
//   - empty writable /etc, /tmp, /var, /run, /root, /home;
//   - /etc/resolv.conf seeded with the configured nameserver.
//
// Anything else under /etc the operator wants visible (/etc/ssl, /etc/hosts,
// nsswitch, passwd, group, ...) must be opted in via ExtraEtcBinds — those
// names are bind-mounted read-only from host /etc.
//
// ExtraBinds is for arbitrary paths outside /etc; useful for sharing state
// dirs (e.g. /var/lib/cloudflare-warp where warp-svc keeps its device
// registration) so the namespace isn't a fully fresh world every run.
//
// If RootMode is NetNSRootHost, ExtraEtcBinds and ExtraBinds are ignored. The
// host filesystem remains visible directly, with only /etc/resolv.conf
// overlaid by a namespace-private bind mount.
type NetNSOptions struct {
	RootMode      NetNSRootMode
	Nameserver    string
	ExtraEtcBinds []string
	ExtraBinds    []BindMount
}

// BindMount describes a single bind mount applied inside the sandbox root.
// Source paths come from the host filesystem; targets are interpreted as
// absolute paths inside the sandbox (parent directories are auto-created).
type BindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// CreateNetNS spawns the anchor goroutine and waits for it to report ready.
// The anchor lives forever (we never UnlockOSThread) so its namespaces stay
// alive even when no other goroutine is currently joined.
func CreateNetNS(opts NetNSOptions, logger *zap.Logger) (*NetNS, error) {
	stagingDir, err := os.MkdirTemp("", "mwarp-root-")
	if err != nil {
		return nil, fmt.Errorf("mktemp staging: %w", err)
	}

	n := &NetNS{
		logger:     logger,
		stagingDir: stagingDir,
		stopCh:     make(chan struct{}),
		taskCh:     make(chan func()),
	}

	type readyMsg struct {
		tid int
		err error
	}
	ready := make(chan readyMsg, 1)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		runtime.LockOSThread()
		// We intentionally never unlock — once this thread enters new
		// namespaces, no other goroutine may run on it.

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- readyMsg{err: fmt.Errorf("unshare newnet: %w", err)}
			return
		}
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			ready <- readyMsg{err: fmt.Errorf("unshare newns: %w", err)}
			return
		}
		// Make the entire mount tree private so nothing we do here can
		// propagate to the host or to other peer namespaces.
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			ready <- readyMsg{err: fmt.Errorf("mount private root: %w", err)}
			return
		}
		if opts.RootMode == NetNSRootHost {
			if err := setupHostRootResolvOverlay(stagingDir, opts); err != nil {
				ready <- readyMsg{err: err}
				return
			}
		} else if err := setupSandboxRoot(stagingDir, opts); err != nil {
			ready <- readyMsg{err: err}
			return
		}

		tid := unix.Gettid()
		ready <- readyMsg{tid: tid}

		// Serve fork+exec requests sequentially. Long-lived child
		// processes spawned this way are reaped via the per-Cmd Wait()
		// in the caller, but their kernel-level "parent thread" is *us*
		// — so PR_SET_PDEATHSIG (set by the caller in SysProcAttr)
		// fires on process shutdown rather than after any short-lived
		// helper goroutine exits.
		for {
			select {
			case <-n.stopCh:
				return
			case fn := <-n.taskCh:
				fn()
			}
		}
	}()

	msg := <-ready
	if msg.err != nil {
		os.RemoveAll(stagingDir)
		return nil, msg.err
	}

	n.NetFD, err = unix.Open(fmt.Sprintf("/proc/%d/ns/net", msg.tid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		close(n.stopCh)
		os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("open net ns: %w", err)
	}
	n.MntFD, err = unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", msg.tid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(n.NetFD)
		close(n.stopCh)
		os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("open mnt ns: %w", err)
	}

	logger.Info("netns ready", zap.Int("anchor_tid", msg.tid))
	return n, nil
}

// setupHostRootResolvOverlay runs inside the anchor thread after CLONE_NEWNS
// and MS_PRIVATE have been applied. It leaves the host filesystem mounted at
// /, but bind-mounts a generated resolv.conf over /etc/resolv.conf inside
// this private mount namespace.
func setupHostRootResolvOverlay(stagingDir string, opts NetNSOptions) error {
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("mkdir staging: %w", err)
	}
	resolvPath := stagingDir + "/resolv.conf"
	if err := os.WriteFile(resolvPath, []byte("nameserver "+opts.Nameserver+"\n"), 0o644); err != nil {
		return fmt.Errorf("write resolv overlay: %w", err)
	}
	if _, err := os.Stat("/etc/resolv.conf"); err != nil {
		return fmt.Errorf("stat /etc/resolv.conf: %w", err)
	}
	if err := unix.Mount(resolvPath, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind resolv overlay: %w", err)
	}
	if err := unix.Mount("", "/etc/resolv.conf", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount resolv overlay ro: %w", err)
	}
	return nil
}

// setupSandboxRoot runs inside the anchor thread, after CLONE_NEWNS and
// MS_PRIVATE have been applied. It builds a tmpfs at stagingDir, populates
// it with the minimal layout described on NetNSOptions, then pivots the
// anchor's root to it. After pivot_root the original root filesystem is
// detached; nothing the anchor (or any process spawned from it) does can
// reach the host's /etc, /var, /run, /home, /opt, etc.
func setupSandboxRoot(stagingDir string, opts NetNSOptions) error {
	if err := unix.Mount("tmpfs", stagingDir, "tmpfs", 0, "mode=755"); err != nil {
		return fmt.Errorf("mount tmpfs root: %w", err)
	}
	mk := func(path string, mode os.FileMode) error {
		full := stagingDir + "/" + path
		if err := os.Mkdir(full, mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		return nil
	}
	for _, d := range []string{
		"usr", "dev", "proc", "sys",
		"etc", "var", "tmp", "run",
		"root", "home", "opt", "srv", "mnt", "media",
		".put_old",
	} {
		mode := os.FileMode(0o755)
		if d == "tmp" {
			mode = 0o1777
		}
		if err := mk(d, mode); err != nil {
			return err
		}
	}

	// /usr — read-only bind. Two-step: bind, then remount RDONLY.
	usrTarget := stagingDir + "/usr"
	if err := unix.Mount("/usr", usrTarget, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind /usr: %w", err)
	}
	if err := unix.Mount("", usrTarget, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("remount /usr ro: %w", err)
	}

	// /dev — do not expose the host device tree to warp. Create only the
	// character devices it needs.
	if err := setupMinimalDev(stagingDir); err != nil {
		return err
	}

	// /proc — fresh procfs. The new netns gets a procfs that reflects
	// itself (e.g. /proc/net/* is the netns's network state).
	if err := unix.Mount("/proc", stagingDir+"/proc", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind /proc: %w", err)
	}

	// /sys — bind from host, read-only. (Mounting fresh sysfs would
	// reflect the new netns's view but warp-svc relies on host-level
	// device info; bind from host is more compatible.)
	if err := unix.Mount("/sys", stagingDir+"/sys", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind /sys: %w", err)
	}
	if err := unix.Mount("", stagingDir+"/sys", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("remount /sys ro: %w", err)
	}

	// /bin /sbin /lib /lib64 → /usr/... (matches modern usr-merge layout).
	for _, link := range []struct{ from, to string }{
		{"bin", "usr/bin"},
		{"sbin", "usr/sbin"},
		{"lib", "usr/lib"},
		{"lib64", "usr/lib64"},
	} {
		if err := os.Symlink(link.to, stagingDir+"/"+link.from); err != nil {
			return fmt.Errorf("symlink %s: %w", link.from, err)
		}
	}

	// /etc/resolv.conf seeded.
	if err := os.WriteFile(stagingDir+"/etc/resolv.conf",
		[]byte("nameserver "+opts.Nameserver+"\n"), 0o644); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}

	// Opt-in extra /etc files/dirs bind-mounted read-only from host.
	for _, name := range opts.ExtraEtcBinds {
		if err := applyBindMount(stagingDir, BindMount{
			Source:   "/etc/" + name,
			Target:   "/etc/" + name,
			ReadOnly: true,
		}); err != nil {
			return err
		}
	}

	// Arbitrary opt-in binds (state dirs, sockets, etc.).
	for _, b := range opts.ExtraBinds {
		if err := applyBindMount(stagingDir, b); err != nil {
			return err
		}
	}

	// pivot_root: enter the staging dir and swap our root with it.
	if err := os.Chdir(stagingDir); err != nil {
		return fmt.Errorf("chdir %s: %w", stagingDir, err)
	}
	if err := unix.PivotRoot(".", ".put_old"); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}
	if err := unix.Unmount("/.put_old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("umount old root: %w", err)
	}
	if err := os.Remove("/.put_old"); err != nil {
		return fmt.Errorf("remove .put_old: %w", err)
	}
	return nil
}

func setupMinimalDev(stagingDir string) error {
	if err := os.MkdirAll(stagingDir+"/dev/net", 0o755); err != nil {
		return fmt.Errorf("mkdir /dev/net: %w", err)
	}
	for _, node := range []struct {
		path         string
		major, minor uint32
		mode         os.FileMode
	}{
		{"/dev/null", 1, 3, 0o666},
		{"/dev/zero", 1, 5, 0o666},
		{"/dev/random", 1, 8, 0o666},
		{"/dev/urandom", 1, 9, 0o666},
		{"/dev/net/tun", 10, 200, 0o666},
	} {
		if err := createCharDevice(stagingDir+node.path, node.mode, node.major, node.minor); err != nil {
			return err
		}
	}
	for _, link := range []struct{ from, to string }{
		{"/dev/stdin", "/proc/self/fd/0"},
		{"/dev/stdout", "/proc/self/fd/1"},
		{"/dev/stderr", "/proc/self/fd/2"},
	} {
		if err := os.Symlink(link.to, stagingDir+link.from); err != nil {
			return fmt.Errorf("symlink %s: %w", link.from, err)
		}
	}
	return nil
}

func createCharDevice(path string, mode os.FileMode, major, minor uint32) error {
	dev := int(unix.Mkdev(major, minor))
	if err := unix.Mknod(path, unix.S_IFCHR|uint32(mode.Perm()), dev); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("mknod %s: %w", path, err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// applyBindMount realizes a single BindMount inside the half-built sandbox
// rooted at stagingDir. Missing host sources are silently skipped (so the
// caller can declare a desirable-but-optional set without separately
// stat'ing each one). Targets are interpreted as paths inside the eventual
// pivoted root; the helper creates whatever empty file/dir is needed at
// stagingDir+target before performing the bind.
func applyBindMount(stagingDir string, b BindMount) error {
	st, err := os.Lstat(b.Source)
	if err != nil {
		return nil // missing on host — silently skip
	}
	dst := stagingDir + b.Target
	if err := os.MkdirAll(filepath_Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", b.Target, err)
	}
	if st.IsDir() {
		if err := os.Mkdir(dst, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("mkdir %s: %w", b.Target, err)
		}
	} else {
		if _, err := os.Stat(dst); err != nil {
			f, err := os.Create(dst)
			if err != nil {
				return fmt.Errorf("touch %s: %w", b.Target, err)
			}
			f.Close()
		}
	}
	if err := unix.Mount(b.Source, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", b.Source, b.Target, err)
	}
	if b.ReadOnly {
		if err := unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("remount %s ro: %w", b.Target, err)
		}
	}
	return nil
}

// filepath_Dir is path/filepath.Dir without importing path/filepath into
// netns.go (kept locally so this file's import set stays minimal).
func filepath_Dir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}

// Close releases namespace fds and signals the anchor to exit.
func (n *NetNS) Close() {
	if n == nil {
		return
	}
	if n.NetFD > 0 {
		unix.Close(n.NetFD)
		n.NetFD = 0
	}
	if n.MntFD > 0 {
		unix.Close(n.MntFD)
		n.MntFD = 0
	}
	select {
	case <-n.stopCh:
	default:
		close(n.stopCh)
	}
	// The staging dir on host is just an empty mount point (the tmpfs
	// only exists inside our private mnt-ns). The anchor thread is
	// permanently locked and stays leaked until process exit; that's the
	// cost of holding the namespace alive.
	if n.stagingDir != "" {
		os.RemoveAll(n.stagingDir)
		n.stagingDir = ""
	}
}

// Run runs fn on a new OS thread that has been setns'd into n's network and
// mount namespaces. The thread is dedicated for the duration of the call and
// exits when fn returns. fn must not call runtime.UnlockOSThread.
func (n *NetNS) Run(fn func() error) error {
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Once we setns into the target network namespace, the thread
		// is permanently tainted. Don't ever unlock so the runtime
		// retires it instead of reusing it.
		//
		// setns(CLONE_NEWNS) requires the calling thread not share its
		// fs_struct with any other thread. Go's runtime creates threads
		// via clone(CLONE_FS), so we must explicitly unshare it first.
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			errCh <- fmt.Errorf("unshare fs: %w", err)
			return
		}
		if err := unix.Setns(n.MntFD, unix.CLONE_NEWNS); err != nil {
			errCh <- fmt.Errorf("setns mnt: %w", err)
			return
		}
		if err := unix.Setns(n.NetFD, unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("setns net: %w", err)
			return
		}
		errCh <- fn()
	}()
	return <-errCh
}

// RunOnAnchor schedules fn to run on the long-lived anchor thread. Use this
// for fork+exec of long-lived child processes that should survive until mwarp
// exits — Pdeathsig (if set) fires when the anchor thread exits, which is at
// process shutdown.
//
// fn must not block; for spawning, do `cmd.Start()` and return.
func (n *NetNS) RunOnAnchor(fn func() error) error {
	errCh := make(chan error, 1)
	select {
	case <-n.stopCh:
		return fmt.Errorf("netns closed")
	case n.taskCh <- func() { errCh <- fn() }:
	}
	return <-errCh
}

// RunNet is like Run but only enters the net namespace (cheaper for dial paths
// where we don't care about /etc/resolv.conf).
func (n *NetNS) RunNet(fn func() error) error {
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(n.NetFD, unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("setns net: %w", err)
			return
		}
		errCh <- fn()
	}()
	return <-errCh
}
