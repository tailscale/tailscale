// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package scutil provides a doctor.Check that runs scutil to print debug
// information about the system on macOS.
package scutil

// Check implements the doctor.Check interface.
type Check struct{}

func (Check) Name() string {
	return "scutil"
}
