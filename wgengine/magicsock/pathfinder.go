// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

// startPathFinder initializes the atomicSendFunc, and
// will eventually kick off a goroutine that monitors whether
// that sendFunc is still the best option for the endpoint
// to use and adjusts accordingly.
func (de *endpoint) startPathFinder() {
	de.pathFinderRunning = true
}
