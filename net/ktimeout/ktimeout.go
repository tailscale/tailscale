// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ktimeout configures kernel TCP stack timeouts via the provided
// control functions. Platform support varies; on unsupported platforms control
// functions may be entirely no-ops.
package ktimeout

import (
	"fmt"
	"syscall"
	"time"
)

// UserTimeout returns a control function that sets the TCP user timeout
// (TCP_USER_TIMEOUT on linux). A user timeout specifies the maximum age of
// unacknowledged data on the connection (either in buffer, or sent but not
// acknowledged) before the connection is terminated. This timer has no effect
// on limiting the lifetime of idle connections. This may be entirely local to
// the network stack or may also apply RFC 5482 options to packets.
func UserTimeout(timeout time.Duration) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return fmt.Errorf("ktimeout.UserTimeout: unsupported network: %s", network)
		}
		var err error
		if e := c.Control(func(fd uintptr) {
			err = SetUserTimeout(fd, timeout)
		}); e != nil {
			return e
		}
		return err
	}
}
