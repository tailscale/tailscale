// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || freebsd || openbsd
// +build linux freebsd openbsd

package dns

import (
	"os/exec"
)

func resolvconfStyle() string {
	if _, err := exec.LookPath("resolvconf"); err != nil {
		return ""
	}
	if _, err := exec.Command("resolvconf", "--version").CombinedOutput(); err != nil {
		// Debian resolvconf doesn't understand --version, and
		// exits with a specific error code.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 99 {
			return "debian"
		}
	}
	// Treat everything else as openresolv, by far the more popular implementation.
	return "openresolv"
}
