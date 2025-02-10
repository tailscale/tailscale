// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package desktop

import "tailscale.com/types/logger"

// NewSessionManager returns a new [SessionManager] for the current platform,
// [ErrNotImplemented] if the platform is not supported, or an error if the
// session manager could not be created.
func NewSessionManager(logger.Logf) (SessionManager, error) {
	return nil, ErrNotImplemented
}
