// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!freebsd,!openbsd,!windows

package dns

import "tailscale.com/types/logger"

func NewOSConfigurator(logger.Logf, string) OSConfigurator {
	// TODO(dmytro): on darwin, we should use a macOS-specific method such as scutil.
	// This is currently not implemented. Editing /etc/resolv.conf does not work,
	// as most applications use the system resolver, which disregards it.
	return NewNoopManager()
}
