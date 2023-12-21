// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// NOTE: linux_{arm64, amd64} are the only two currently supported archs due to missing
// support in upstream dependencies.

// TODO(#8502): add support for more architectures
//go:build linux && !(arm64 || amd64)

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
func detectNetfilter() (int, error) {
	return 0, ErrUnsupported
}

// DebugIptables is not supported on non-Linux platforms.
func debugIptables(logf logger.Logf) error {
	return ErrUnsupported
}

// DetectIptables is not supported on non-Linux platforms.
func detectIptables() (int, error) {
	return 0, ErrUnsupported
}
