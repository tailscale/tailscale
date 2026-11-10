// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"fmt"
	"math"
	"time"
)

// SetUserTimeoutChecked sets the TCP user timeout on fd, or returns an error
// wrapping errors.ErrUnsupported if this platform or socket does not support it.
// Unlike SetUserTimeout, it does not silently succeed on unsupported platforms.
// Success does not imply keepalive offload or any application-health guarantee.
//
// timeout must be a nonnegative whole number of milliseconds no greater than
// math.MaxInt32 milliseconds. Zero restores the kernel's default behavior.
// Invalid values are rejected before touching the socket.
func SetUserTimeoutChecked(fd uintptr, timeout time.Duration) error {
	if timeout < 0 || timeout%time.Millisecond != 0 || timeout/time.Millisecond > math.MaxInt32 {
		return fmt.Errorf("invalid TCP user timeout %v: want whole milliseconds in [0, %d]", timeout, math.MaxInt32)
	}
	return setUserTimeoutChecked(fd, timeout)
}
