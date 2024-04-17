// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package envknob

import (
	"errors"
	"runtime"

	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// CanRunTailscaleSSH reports whether serving a Tailscale SSH server is
// supported for the current os/distro.
func CanRunTailscaleSSH() error {
	switch runtime.GOOS {
	case "linux":
		if distro.Get() == distro.Synology && !UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on Synology.")
		}
		if distro.Get() == distro.QNAP && !UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on QNAP.")
		}
		// otherwise okay
	case "darwin":
		// okay only in tailscaled mode for now.
		if version.IsSandboxedMacOS() {
			return errors.New("The Tailscale SSH server does not run in sandboxed Tailscale GUI builds.")
		}
	case "freebsd", "openbsd":
	default:
		return errors.New("The Tailscale SSH server is not supported on " + runtime.GOOS)
	}
	if !CanSSHD() {
		return errors.New("The Tailscale SSH server has been administratively disabled.")
	}
	return nil
}
