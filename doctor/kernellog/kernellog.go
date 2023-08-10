// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kernellog provides a doctor.Check that checks for errors in the
// system's kernel log.
package kernellog

// Check implements the doctor.Check interface.
type Check struct{}

func (Check) Name() string {
	return "kernellog"
}
