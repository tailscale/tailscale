// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

// startPathFinder initializes the atomicSendFunc, and
// will eventually kick off a goroutine that monitors whether
// that sendFunc is still the best option for the endpoint
// to use and adjusts accordingly.
func (de *endpoint) startPathFinder() {
	de.pathFinderRunning = true
}
