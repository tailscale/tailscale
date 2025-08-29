// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

type SuggestExitNode struct {
	// Priority is the relative priority of this exit node. Nodes with a
	// higher priority are preferred over nodes with a lower priority, nodes
	// of equal probability may be selected arbitrarily. A priority of 0
	// means the exit node has no a priority preference and a negative
	// priority is not allowed.
	Priority int `json:",omitempty"`
}
