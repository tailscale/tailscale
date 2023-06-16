// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// NOTE: linux_{386,loong64,arm,armbe} are currently unsupported due to missing
// support in upstream dependencies.

//go:build !linux || (linux && (386 || loong64 || arm || armbe))

package linuxfw

import (
	"errors"

	"tailscale.com/types/logger"
)

// ErrUnsupported is the error returned from all functions on non-Linux
// platforms.
var ErrUnsupported = errors.New("linuxfw:unsupported")

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
