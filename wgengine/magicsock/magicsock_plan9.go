// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package magicsock

// shouldRebind returns if the error is one that is known to be healed by a
// rebind, and if so also returns a resason string for the rebind.
func shouldRebind(err error) (ok bool, reason string) {
	return false, ""
}
