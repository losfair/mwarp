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

func warpCommandEnv() []string {
	env := append([]string(nil), os.Environ()...)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + warpBinDir + ":" + strings.TrimPrefix(kv, "PATH=")
			return env
		}
	}
	return append(env, "PATH="+warpBinDir)
}
