package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const warpBinDir = "/warp"

func prepareWarpCommandBinds(cfg *Config) ([]BindMount, error) {
	var binds []BindMount
	seen := map[string]string{}

	add := func(b *BindMount) error {
		if b == nil {
			return nil
		}
		if prev, ok := seen[b.Target]; ok {
			if prev != b.Source {
				return fmt.Errorf("warp command bind target conflict: %s maps both %s and %s", b.Target, prev, b.Source)
			}
			return nil
		}
		seen[b.Target] = b.Source
		binds = append(binds, *b)
		return nil
	}

	raw, bind, err := prepareWarpSvcCommand(cfg.WarpSvcCmd)
	if err != nil {
		return nil, err
	}
	cfg.WarpSvcCmd = raw
	if err := add(bind); err != nil {
		return nil, err
	}

	cli, bind, err := prepareWarpCLICommand(cfg.WarpCli)
	if err != nil {
		return nil, err
	}
	cfg.WarpCli = cli
	if err := add(bind); err != nil {
		return nil, err
	}

	return binds, nil
}

func prepareWarpSvcCommand(raw string) (string, *BindMount, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw, nil, nil
	}
	parts, err := splitArgs(raw)
	if err != nil {
		return "", nil, err
	}
	source, target, err := prepareWarpExecutable(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf("resolve warp-svc command: %w", err)
	}
	parts[0] = target
	return joinArgs(parts), &BindMount{Source: source, Target: target, ReadOnly: true}, nil
}

func prepareWarpCLICommand(cli string) (string, *BindMount, error) {
	cli = strings.TrimSpace(cli)
	if cli == "" {
		return cli, nil, nil
	}
	source, target, err := prepareWarpExecutable(cli)
	if err != nil {
		return "", nil, fmt.Errorf("resolve warp-cli command: %w", err)
	}
	return target, &BindMount{Source: source, Target: target, ReadOnly: true}, nil
}

func prepareWarpExecutable(cmd string) (string, string, error) {
	resolved, err := exec.LookPath(cmd)
	if err != nil {
		return "", "", err
	}
	source, err := filepath.Abs(resolved)
	if err != nil {
		return "", "", err
	}
	base := filepath.Base(source)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", "", fmt.Errorf("invalid executable path %q", source)
	}
	return source, path.Join(warpBinDir, base), nil
}

func joinArgs(args []string) string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = quoteArg(arg)
	}
	return strings.Join(out, " ")
}

func quoteArg(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\"\\") {
		return arg
	}
	arg = strings.ReplaceAll(arg, `\`, `\\`)
	arg = strings.ReplaceAll(arg, `"`, `\"`)
	return `"` + arg + `"`
}

// warpCommandEnv returns the environment passed to warp-svc / warp-cli.
// Only PATH is provided; nothing from the parent environment is forwarded
// (no WG_* secrets, no proxy URLs, no shell state, etc.) so none of it
// lands in the child's /proc/<pid>/environ.
//
// PATH is constructed so the sandbox bind-mount directory is searched
// first; the host PATH is appended only as a fallback for libc/dynamic
// loader lookups that might consult it.
func warpCommandEnv() []string {
	if hostPath, ok := os.LookupEnv("PATH"); ok {
		return []string{"PATH=" + warpBinDir + ":" + hostPath}
	}
	return []string{"PATH=" + warpBinDir}
}
