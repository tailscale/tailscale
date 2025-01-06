// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package magicsock

// maybeRebindOnError performs a rebind and restun if the error is defined and
// any conditionals are met.
func (c *Conn) maybeRebindOnError(os string, err error) bool {
	return false
}
