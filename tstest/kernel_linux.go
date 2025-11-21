// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tstest

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelVersion returns the major, minor, and patch version of the Linux kernel.
// It returns (0, 0, 0) if the version cannot be determined.
func KernelVersion() (major, minor, patch int) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0, 0
	}
	release := unix.ByteSliceToString(uname.Release[:])

	// Parse version string (e.g., "5.15.0-...")
	parts := strings.Split(release, ".")
	if len(parts) < 3 {
		return 0, 0, 0
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0
	}

	// Patch version may have additional info after a hyphen (e.g., "0-76-generic")
	// Extract just the numeric part before any hyphen
	patchStr, _, _ := strings.Cut(parts[2], "-")

	patch, err = strconv.Atoi(patchStr)
	if err != nil {
		return 0, 0, 0
	}

	return major, minor, patch
}
