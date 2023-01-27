// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !freebsd && !openbsd && !windows && !darwin

package dns

import "tailscale.com/types/logger"

func NewOSConfigurator(logger.Logf, string) (OSConfigurator, error) {
	// TODO(dmytro): on darwin, we should use a macOS-specific method such as scutil.
	// This is currently not implemented. Editing /etc/resolv.conf does not work,
	// as most applications use the system resolver, which disregards it.
	return NewNoopManager()
}
