// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package paths returns platform and user-specific default paths to
// Tailscale files and directories.
package paths

import (
	"os"
	"path/filepath"
	"runtime"

	"tailscale.com/syncs"
	"tailscale.com/version/distro"
)

// AppSharedDir is a string set by the iOS or Android app on start
// containing a directory we can read/write in.
var AppSharedDir syncs.AtomicValue[string]

// DefaultTailscaledSocket returns the path to the tailscaled Unix socket
// or the empty string if there's no reasonable default.
func DefaultTailscaledSocket() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if runtime.GOOS == "darwin" {
		return "/var/run/tailscaled.socket"
	}
	switch distro.Get() {
	case distro.Synology:
		// TODO(maisem): be smarter about this. We can parse /etc/VERSION.
		const dsm6Sock = "/var/packages/Tailscale/etc/tailscaled.sock"
		const dsm7Sock = "/var/packages/Tailscale/var/tailscaled.sock"
		if fi, err := os.Stat(dsm6Sock); err == nil && !fi.IsDir() {
			return dsm6Sock
		}
		if fi, err := os.Stat(dsm7Sock); err == nil && !fi.IsDir() {
			return dsm7Sock
		}
	case distro.Gokrazy:
		return "/perm/tailscaled/tailscaled.sock"
	}
	if fi, err := os.Stat("/var/run"); err == nil && fi.IsDir() {
		return "/var/run/tailscale/tailscaled.sock"
	}
	return "tailscaled.sock"
}

var stateFileFunc func() string

// DefaultTailscaledStateFile returns the default path to the
// tailscaled state file, or the empty string if there's no reasonable
// default value.
func DefaultTailscaledStateFile() string {
	if f := stateFileFunc; f != nil {
		return f()
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "Tailscale", "server-state.conf")
	}
	return ""
}

// MkStateDir ensures that dirPath, the daemon's configuration directory
// containing machine keys etc, both exists and has the correct permissions.
// We want it to only be accessible to the user the daemon is running under.
func MkStateDir(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}

	return ensureStateDirPerms(dirPath)
}
