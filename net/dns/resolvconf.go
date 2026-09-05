// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || freebsd || openbsd

package dns

import (
	"bytes"
	"os/exec"
	"path/filepath"
)

func resolvconfStyle() string {
	path, err := exec.LookPath("resolvconf")
	if err != nil {
		return ""
	}
	if resolvconfIsSystemdResolved(path) {
		// systemd-resolved ships a resolvconf compatibility symlink to
		// resolvectl. Treating that shim as openresolv makes us invoke
		// resolvconf with incompatible flags.
		return ""
	}
	output, err := exec.Command("resolvconf", "--version").CombinedOutput()
	if err != nil {
		// Debian resolvconf doesn't understand --version, and
		// exits with a specific error code.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 99 {
			return "debian"
		}
	}
	if bytes.HasPrefix(output, []byte("Debian resolvconf")) {
		return "debian"
	}
	// Treat everything else as openresolv, by far the more popular implementation.
	return "openresolv"
}

func resolvconfIsSystemdResolved(path string) bool {
	resolvedPath, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.Base(resolvedPath) == "resolvectl"
}
