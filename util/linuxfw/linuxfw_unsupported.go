// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// NOTE: linux_386 and linux_loong64 are currently unsupported due to missing
// support in upstream dependencies.

//go:build !linux || (linux && (386 || loong64))

package linuxfw

import (
	"tailscale.com/types/logger"
)

// DebugNetfilter is not supported on non-Linux platforms.
func DebugNetfilter(logf logger.Logf) error {
	return ErrUnsupported
}

// DetectNetfilter is not supported on non-Linux platforms.
func DetectNetfilter() (int, error) {
	return 0, ErrUnsupported
}

// DebugIptables is not supported on non-Linux platforms.
func DebugIptables(logf logger.Logf) error {
	return ErrUnsupported
}

// DetectIptables is not supported on non-Linux platforms.
func DetectIptables() (int, error) {
	return 0, ErrUnsupported
}
