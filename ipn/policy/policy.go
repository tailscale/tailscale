// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policy contains various policy decisions that need to be
// shared between the node client & control server.
package policy

import (
	"tailscale.com/tailcfg"
)

// IsInterestingService reports whether service s on the given operating
// system (a version.OS value) is an interesting enough port to report
// to our peer nodes for discovery purposes.
func IsInterestingService(s tailcfg.Service, os string) bool {
	switch s.Proto {
	case tailcfg.PeerAPI4, tailcfg.PeerAPI6, tailcfg.PeerAPIDNS:
		return true
	}
	if s.Proto != tailcfg.TCP {
		return false
	}
	if os != "windows" {
		// For non-Windows machines, assume all TCP listeners
		// are interesting enough. We don't see listener spam
		// there.
		return true
	}
	// Windows has tons of TCP listeners. We need to move to a denylist
	// model later, but for now we just allow some common ones:
	switch s.Port {
	case 22, // ssh
		80,    // http
		443,   // https (but no hostname, so little useless)
		3389,  // rdp
		5900,  // vnc
		32400, // plex

		// And now some arbitrary HTTP dev server ports:
		// Eventually we'll remove this and make all ports
		// work, once we nicely filter away noisy system
		// ports.
		8000, 8080, 8443, 8888:
		return true
	}
	return false
}
