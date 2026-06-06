// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package router contains constants that describe a router in the routecheck report.
package router

import "fmt"

// Reachability reports whether a router is reachable.
type Reachability int

const (
	// Unknown is a router whose reachability is unknown.
	// This router is new and we have yet to probe it.
	Unknown Reachability = iota
	// Reachable is a router that is reachable from this node.
	Reachable
	// Unreachable is a router that is unreachable from this node.
	// This router is not responding to probes.
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
