package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// The registration tests exercise the real exec and output-handling path;
// only namespace entry is bypassed so they do not require root privileges.
type directWarpCommandNamespace struct{}

func (directWarpCommandNamespace) Run(fn func() error) error { return fn() }

func TestRegisterWarpExistingRegistrationCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name     string
		message  string
		exitCode int
		wantOK   bool
	}{
		{"new registration", "Success", 0, true},
		{"legacy existing registration", "Error: already registered", 1, true},
		{"alternate existing registration", "Error: registration already exists", 1, true},
		{"current existing registration", "Error: Old registration is still around. Try running: \"warp-cli registration delete\"", 1, true},
		{"unrelated failure", "Error: registration API unavailable", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "warp-cli-fixture")
			text := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s' >&2\nexit %d\n", tc.message, tc.exitCode)
			if err := os.WriteFile(script, []byte(text), 0700); err != nil {
				t.Fatal(err)
			}
			err := RegisterWarp(directWarpCommandNamespace{}, script, 1, 0, zap.NewNop())
			if (err == nil) != tc.wantOK {
				t.Fatalf("registration success=%v, want %v; err=%v", err == nil, tc.wantOK, err)
			}
		})
	}
}
