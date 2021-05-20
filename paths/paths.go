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
	"sync/atomic"
)

// AppSharedDir is a string set by the iOS or Android app on start
// containing a directory we can read/write in.
var AppSharedDir atomic.Value

// DefaultTailscaledSocket returns the path to the tailscaled Unix socket
// or the empty string if there's no reasonable default.
func DefaultTailscaledSocket() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if runtime.GOOS == "darwin" {
		return "/var/run/tailscaled.socket"
	}
	if runtime.GOOS == "linux" {
		// TODO(crawshaw): does this path change with DSM7?
		const synologySock = "/volume1/@appstore/Tailscale/var/tailscaled.sock" // SYNOPKG_PKGDEST in scripts/installer
		if fi, err := os.Stat(filepath.Dir(synologySock)); err == nil && fi.IsDir() {
			return synologySock
		}
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
		return filepath.Join(os.Getenv("LocalAppData"), "Tailscale", "server-state.conf")
	}
	return ""
}
