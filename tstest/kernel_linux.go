// Copyright (c) Tailscale Inc & contributors
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
	return parseKernelVersion(release)
}

// parseKernelVersion parses a Linux kernel version string like "6.12.73+deb13-amd64"
// or "5.15.0-76-generic" and returns the major, minor, and patch components.
// It returns (0, 0, 0) if the version cannot be parsed.
func parseKernelVersion(release string) (major, minor, patch int) {
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

	// Patch version may have additional info after a hyphen or plus (e.g., "0-76-generic" or "41+deb13-amd64")
	// Extract just the numeric part before any hyphen or plus
	patchStr := parts[2]
	if idx := strings.IndexAny(patchStr, "-+"); idx != -1 {
		patchStr = patchStr[:idx]
	}

	patch, err = strconv.Atoi(patchStr)
	if err != nil {
		return 0, 0, 0
	}

	return major, minor, patch
}
