package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
)

// ansiRE strips terminal escape sequences from rust tracing output so the
// log file stays parseable.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// streamSubprocessLogs reads lines from r and emits one log entry per line
// under the given subprocess name. Levels are inferred from the rust tracing
// level token (`INFO`, `WARN`, etc.) if present, otherwise default to debug
// (warp-svc is extremely chatty).
func streamSubprocessLogs(name, stream string, r io.ReadCloser, logger *zap.Logger) {
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		clean := strings.TrimRight(ansiRE.ReplaceAllString(raw, ""), " \t\r")
		if clean == "" {
			continue
		}
		level := inferRustLevel(clean)
		if ce := logger.Check(level, name); ce != nil {
			ce.Write(zap.String("stream", stream), zap.String("line", clean))
		}
	}
}

// logSubprocessBuffer flushes a captured stdout/stderr buffer (typically from
// a short-lived child process) line by line through streamSubprocessLogs's
// formatting/level inference.
func logSubprocessBuffer(name, stream string, buf *bytes.Buffer, logger *zap.Logger) {
	if buf.Len() == 0 {
		return
	}
	streamSubprocessLogs(name, stream, io.NopCloser(buf), logger)
}

func inferRustLevel(line string) zapcore.Level {
	switch {
	case strings.Contains(line, " ERROR "):
		return zapcore.ErrorLevel
	case strings.Contains(line, " WARN "):
		return zapcore.WarnLevel
	case strings.Contains(line, " INFO "):
		return zapcore.InfoLevel
	case strings.Contains(line, " TRACE "):
		return zapcore.DebugLevel
	default:
		// DEBUG and unknown — warp-svc emits DEBUG by default.
		return zapcore.DebugLevel
	}
}

// StartWarpSvc spawns the warp service in the netns. Its stdout/stderr are
// piped into the configured zap logger (one log entry per line) so the user's
// terminal stays clean and the messages are still recoverable from --log-file.
// The returned Cmd is the long-lived process — caller should Wait on it
// (typically in a goroutine that signals the supervisor on exit).
func StartWarpSvc(ns *NetNS, raw string, logger *zap.Logger) (*exec.Cmd, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		logger.Info("warp-svc disabled")
		return nil, nil
	}
	parts, err := splitArgs(raw)
	if err != nil {
		return nil, err
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/null: %w", err)
	}
	defer devNull.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("pipe(stdout): %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return nil, fmt.Errorf("pipe(stderr): %w", err)
	}

	var c *exec.Cmd
	var startErr error
	err = ns.RunOnAnchor(func() error {
		warpSvcCaps := capMask(unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE)
		if err := restrictCurrentThreadCaps(warpSvcCaps); err != nil {
			return err
		}
		c = exec.Command(parts[0], parts[1:]...)
		c.Stdin = devNull
		c.Stdout = stdoutW
		c.Stderr = stderrW
		c.Env = warpCommandEnv()
		c.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig:   unix.SIGKILL,
			Setpgid:     true,
			AmbientCaps: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE},
		}
		startErr = c.Start()
		return startErr
	})
	// Close our copy of the write ends — the child has dup'd them. This
	// is required for our pipe readers to ever see EOF when warp-svc
	// exits.
	_ = stdoutW.Close()
	_ = stderrW.Close()
	if err != nil {
		stdoutR.Close()
		stderrR.Close()
		return nil, fmt.Errorf("start warp-svc: %w", err)
	}
	go streamSubprocessLogs("warp-svc", "stdout", stdoutR, logger)
	go streamSubprocessLogs("warp-svc", "stderr", stderrR, logger)
	logger.Info("warp-svc started", zap.Int("pid", c.Process.Pid), zap.String("cmd", raw))
	return c, nil
}

// RegisterWarp ensures warp-svc has a device registration before we try to
// connect. With the sandboxed netns, /var/lib/cloudflare-warp is a fresh
// tmpfs on every invocation, so the registration must be created on demand
// (`warp-cli registration new`). If a persistent state dir is bind-mounted
// in and a registration is already present, the call is a no-op from
// warp-cli's perspective ("already registered" — we tolerate it).
//
// Retries with the same cadence as ConnectWarp so we ride out warp-svc's
// IPC socket coming up.
func RegisterWarp(ns *NetNS, cli string, acceptTOS bool, retries, delaySeconds int, logger *zap.Logger) error {
	cli = strings.TrimSpace(cli)
	if cli == "" {
		return nil
	}
	args := []string{}
	if acceptTOS {
		args = append(args, "--accept-tos")
	}
	args = append(args, "registration", "new")

	var lastErr error
	for i := 0; i < retries; i++ {
		var stdout, stderr bytes.Buffer
		var runErr error
		err := ns.Run(func() error {
			cmd := exec.Command(cli, args...)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			cmd.Env = warpCommandEnv()
			runErr = cmd.Run()
			return runErr
		})
		logSubprocessBuffer("warp-cli", "stdout", &stdout, logger)
		logSubprocessBuffer("warp-cli", "stderr", &stderr, logger)
		if err == nil && runErr == nil {
			logger.Info("warp-cli registration ok")
			return nil
		}
		combined := strings.ToLower(stderr.String() + stdout.String())
		if strings.Contains(combined, "already registered") ||
			strings.Contains(combined, "registration already") {
			logger.Info("warp-cli registration already present")
			return nil
		}
		// Daemon may not have opened its IPC socket yet — retry.
		lastErr = fmt.Errorf("warp-cli registration: %w", runErr)
		logger.Warn("warp-cli registration failed",
			zap.Int("attempt", i+1),
			zap.Error(lastErr))
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("warp-cli registration: no attempts")
	}
	return lastErr
}

// ConnectWarp attempts `warp-cli [--accept-tos] connect` with the configured
// retry/delay. Returns the last error if all attempts failed.
func ConnectWarp(ns *NetNS, cli string, acceptTOS bool, retries, delaySeconds int, logger *zap.Logger) error {
	cli = strings.TrimSpace(cli)
	if cli == "" {
		logger.Info("warp-cli connect skipped (empty cli)")
		return nil
	}
	args := []string{}
	if acceptTOS {
		args = append(args, "--accept-tos")
	}
	args = append(args, "connect")
	useAccept := acceptTOS

	var lastErr error
	for i := 0; i < retries; i++ {
		var stdout, stderr bytes.Buffer
		var runErr error
		err := ns.Run(func() error {
			cmd := exec.Command(cli, args...)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			cmd.Env = warpCommandEnv()
			runErr = cmd.Run()
			return runErr
		})
		logSubprocessBuffer("warp-cli", "stdout", &stdout, logger)
		logSubprocessBuffer("warp-cli", "stderr", &stderr, logger)
		if err == nil && runErr == nil {
			logger.Info("warp-cli connect ok")
			return nil
		}
		combined := stderr.String()
		if useAccept && (strings.Contains(strings.ToLower(combined), "unknown flag") ||
			strings.Contains(strings.ToLower(combined), "unknown option") ||
			strings.Contains(strings.ToLower(combined), "flag provided but not defined")) {
			logger.Info("warp-cli does not support --accept-tos, retrying without it")
			useAccept = false
			args = []string{"connect"}
			continue
		}
		lastErr = fmt.Errorf("warp-cli %v failed: %w", args, runErr)
		logger.Warn("warp-cli connect failed",
			zap.Int("attempt", i+1),
			zap.Error(lastErr))
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("warp-cli connect: no attempts made")
	}
	return lastErr
}

// splitArgs is a minimal POSIX-ish argv splitter (handles double quotes and
// backslash-escapes).
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur []rune
	inQuote := false
	escape := false
	for _, r := range s {
		if escape {
			cur = append(cur, r)
			escape = false
			continue
		}
		switch {
		case r == '\\' && !escape:
			escape = true
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if len(cur) > 0 {
				out = append(out, string(cur))
				cur = cur[:0]
			}
		default:
			cur = append(cur, r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in command")
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return out, nil
}
