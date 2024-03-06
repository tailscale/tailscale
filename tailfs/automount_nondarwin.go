// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package tailfs

// DefaultAutomountPath returns the default automount path. If blank, that
// means TailFS is disabled on this platform.
func DefaultAutomountPath() string {
	return ""
}

func MountShares(location string, username string) {
	// Do nothing.
}

func UnmountShares(location string) {
	// Do nothing.
}
