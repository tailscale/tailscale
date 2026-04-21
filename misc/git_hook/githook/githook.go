// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package githook contains the shared implementation of Tailscale's git
// hooks. The tailscale/tailscale and tailscale/corp repositories each have
// a thin main package that dispatches to this one, calling individual
// hook functions with per-repo arguments as needed.
package githook

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Launcher is the canonical bytes of launcher.sh. Downstream repos
// (e.g. tailscale/corp) rely on these bytes at install time.
//
//go:embed launcher.sh
var Launcher []byte

// HookVersion is the shared version of this package and launcher.sh.
// Bump HOOK_VERSION on any change under this package.
//
//go:embed HOOK_VERSION
var HookVersion string

// RunLocalHook runs an optional user-supplied hook at
// .git/hooks/<name>.local, if present.
func RunLocalHook(hookName string, args []string) error {
	cmdPath, err := os.Executable()
	if err != nil {
		return err
	}
	localHookPath := filepath.Join(filepath.Dir(cmdPath), hookName+".local")
	if _, err := os.Stat(localHookPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("checking for local hook: %w", err)
	}

	cmd := exec.Command(localHookPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running local hook %q: %w", localHookPath, err)
	}
	return nil
}
