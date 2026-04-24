// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package peernode

import "fmt"

// Reachability reports whether a peer node is reachable.
type Reachability int

const (
	// Unknown is a peer node whose reachability is unknown.
	// This peer is new and we have yet to probe it.
	Unknown Reachability = iota
	// Reachable is a peer node that is reachable from this node.
	Reachable
	// Unreachable is a peer node that is unreachable from this node.
	// This peer is not responding to probes.
	Unreachable
)

// String implements [fmt.Stringer].
func (r Reachability) String() string {
	switch r {
	case Unknown:
		return "Unknown"
	case Reachable:
		return "Reachable"
	case Unreachable:
		return "Unreachable"
	default:
		panic(fmt.Sprintf("unknown %#v", r))
	}
}

// IsReachable reports if r is [Reachable].
func (r Reachability) IsReachable() bool {
	return r == Reachable
}
