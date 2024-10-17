// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package featureknob provides a facility to control whether features
// can run based on either an envknob or running OS / distro.
package featureknob

import (
	"errors"
	"runtime"

	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// CanRunTailscaleSSH reports whether serving a Tailscale SSH server is
// supported for the current os/distro.
func CanRunTailscaleSSH() error {
	switch runtime.GOOS {
	case "linux":
		if distro.Get() == distro.Synology && !envknob.UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on Synology.")
		}
		if distro.Get() == distro.QNAP && !envknob.UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on QNAP.")
		}

		// Setting SSH on Home Assistant causes trouble on startup
		// (since the flag is not being passed to `tailscale up`).
		// Although Tailscale SSH does work here,
		// it's not terribly useful since it's running in a separate container.
		if hostinfo.GetEnvType() == hostinfo.HomeAssistantAddOn {
			return errors.New("The Tailscale SSH server does not run on HomeAssistant.")
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
	if !envknob.CanSSHD() {
		return errors.New("The Tailscale SSH server has been administratively disabled.")
	}
	return nil
}

// CanUseExitNode reports whether using an exit node is supported for the
// current os/distro.
func CanUseExitNode() error {
	switch dist := distro.Get(); dist {
	case distro.Synology, // see https://github.com/tailscale/tailscale/issues/1995
		distro.QNAP,
		distro.Unraid:
		return errors.New("Tailscale exit nodes cannot be used on " + string(dist))
	}

	if hostinfo.GetEnvType() == hostinfo.HomeAssistantAddOn {
		return errors.New("Tailscale exit nodes cannot be used on HomeAssistant.")
	}

	return nil
}
