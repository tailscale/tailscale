// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package paths

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func init() {
	stateFileFunc = stateFileUnix
}

func statePath() string {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/tailscale/tailscaled.state"
	case "freebsd", "openbsd":
		return "/var/db/tailscale/tailscaled.state"
	case "darwin":
		return "/Library/Tailscale/tailscaled.state"
	default:
		return ""
	}
}

func stateFileUnix() string {
	path := statePath()
	if path == "" {
		return ""
	}

	try := path
	for i := 0; i < 3; i++ { // check writability of the file, /var/lib/tailscale, and /var/lib
		err := unix.Access(try, unix.O_RDWR)
		if err == nil {
			return path
		}
		try = filepath.Dir(try)
	}

	if os.Getuid() == 0 {
		return ""
	}

	// For non-root users, fall back to $XDG_DATA_HOME/tailscale/*.
	return filepath.Join(xdgDataHome(), "tailscale", "tailscaled.state")
}

func xdgDataHome() string {
	if e := os.Getenv("XDG_DATA_HOME"); e != "" {
		return e
	}
	return filepath.Join(os.Getenv("HOME"), ".local/share")
}

func ensureStateDirPerms(dirPath string) error {
	if filepath.Base(dirPath) != "tailscale" {
		return nil
	}

	return os.Chmod(dirPath, 0700)
}
