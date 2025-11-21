// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package tstest

// KernelVersion returns (0, 0, 0) on unsupported platforms.
func KernelVersion() (major, minor, patch int) {
	return 0, 0, 0
}
