// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !wasm && !windows && !plan9

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

func init() {
	getSSHClientEnvVar = func() string {
		if os.Getenv("SUDO_USER") == "" {
			// No sudo, just check the env.
			return os.Getenv("SSH_CLIENT")
		}
		if runtime.GOOS != "linux" {
			// TODO(maisem): implement this for other platforms. It's not clear
			// if there is a way to get the environment for a given process on
			// darwin and bsd.
			return ""
		}
		// SID is the session ID of the user's login session.
		// It is also the process ID of the original shell that the user logged in with.
		// We only need to check the environment of that process.
		sid, err := unix.Getsid(os.Getpid())
		if err != nil {
			return ""
		}
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(sid), "environ"))
		if err != nil {
			return ""
		}
		prefix := []byte("SSH_CLIENT=")
		for _, env := range bytes.Split(b, []byte{0}) {
			if bytes.HasPrefix(env, prefix) {
				return string(env[len(prefix):])
			}
		}
		return ""
	}
}
