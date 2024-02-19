// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"time"

	"golang.org/x/sys/unix"
)

// SetUserTimeout sets the TCP_USER_TIMEOUT option on the given file descriptor.
func SetUserTimeout(fd uintptr, timeout time.Duration) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_TCP, unix.TCP_USER_TIMEOUT, int(timeout/time.Millisecond))
}
