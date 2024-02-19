// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package ktimeout

import (
	"time"
)

// SetUserTimeout is a no-op on this platform.
func SetUserTimeout(fd uintptr, timeout time.Duration) error {
	return nil
}
