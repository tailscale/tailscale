// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package magicsock

import (
	"errors"
	"syscall"
	"time"
)

// maybeRebindOnError performs a rebind and restun if the error is defined and
// any conditionals are met.
func (c *Conn) maybeRebindOnError(os string, err error) bool {
	switch {
	case errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ENOTCONN):
		// EPIPE/ENOTCONN are common errors when a send fails due to a closed
		// socket. There is some platform and version inconsistency in which
		// error is returned, but the meaning is the same.
		why := "broken-pipe-rebind"
		c.logf("magicsock: performing %q", why)
		c.Rebind()
		go c.ReSTUN(why)
		return true
	case errors.Is(err, syscall.EPERM):
		why := "operation-not-permitted-rebind"
		switch os {
		// We currently will only rebind and restun on a syscall.EPERM if it is experienced
		// on a client running darwin.
		// TODO(charlotte, raggi): expand os options if required.
		case "darwin":
			// TODO(charlotte): implement a backoff, so we don't end up in a rebind loop for persistent
			// EPERMs.
			if c.lastEPERMRebind.Load().Before(time.Now().Add(-5 * time.Second)) {
				c.logf("magicsock: performing %q", why)
				c.lastEPERMRebind.Store(time.Now())
				c.Rebind()
				go c.ReSTUN(why)
				return true
			}
		default:
			c.logf("magicsock: not performing %q", why)
			return false
		}
	}
	return false
}
