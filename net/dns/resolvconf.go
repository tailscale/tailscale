// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || freebsd || openbsd
// +build linux freebsd openbsd

package dns

import (
	"os/exec"

	"tailscale.com/types/logger"
)

func getResolvConfVersion() ([]byte, error) {
	return exec.Command("resolvconf", "--version").CombinedOutput()
}

func newResolvconfManager(logf logger.Logf, getResolvConfVersion func() ([]byte, error)) (OSConfigurator, error) {
	_, err := getResolvConfVersion()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 99 {
			// Debian resolvconf doesn't understand --version, and
			// exits with a specific error code.
			return newDebianResolvconfManager(logf)
		}
	}
	// If --version works, or we got some surprising error while
	// probing, use openresolv. It's the more common implementation,
	// so in cases where we can't figure things out, it's the least
	// likely to misbehave.
	return newOpenresolvManager()
}
