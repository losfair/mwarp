package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// RunInNS executes argv in the netns, attaching the current stdio (which is
// typically the user's PTY). Returns the child's exit code.
func RunInNS(ns *NetNS, argv []string, logger *zap.Logger) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("run: no command provided")
	}

	stdinIsTTY := isatty(int(os.Stdin.Fd()))

	var cmd *exec.Cmd
	var startErr error
	err := ns.RunOnAnchor(func() error {
		cmd = exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: unix.SIGKILL,
		}
		if stdinIsTTY {
			cmd.SysProcAttr.Setpgid = true
			cmd.SysProcAttr.Foreground = true
			cmd.SysProcAttr.Ctty = int(os.Stdin.Fd())
		}
		startErr = cmd.Start()
		return startErr
	})
	if err != nil {
		return 0, fmt.Errorf("start child: %w", err)
	}
	logger.Info("child started", zap.Int("pid", cmd.Process.Pid))

	// If we're not the foreground process, forward signals to the child.
	var sigCh chan os.Signal
	if !stdinIsTTY {
		sigCh = make(chan os.Signal, 4)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		go func() {
			for s := range sigCh {
				if cmd.Process != nil {
					_ = cmd.Process.Signal(s)
				}
			}
		}()
	}

	waitErr := cmd.Wait()
	if sigCh != nil {
		signal.Stop(sigCh)
		close(sigCh)
	}

	if waitErr == nil {
		return 0, nil
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
			return status.ExitStatus(), nil
		}
	}
	return 1, waitErr
}

func isatty(fd int) bool {
	var t unix.Termios
	_, _, err := unix.Syscall6(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCGETS), uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return err == 0
}
