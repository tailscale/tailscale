// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"slices"

	"tailscale.com/tailcfg"
	_ "tailscale.com/types/netmap"
)

// DiffNodeViews compares two slices of old and new nodes
// and returns the nodes that were added, modified, and removed.
// The returned slices are sorted by [Node.ID].
//
// BUG(sfllaw): This function should be used sparingly as a stopgap measure,
// because the incremental processing in [LocalBackend.UpdateNetmapDelta] only
// handles modifications and not additions or removals as of 2026-05-13.
// See tailscale/tailscale#1909 and tailscale/tailscale#12542.
//
// TODO(sfllaw): After tailscale/tailscale#19607 is merged, use its mechanism
// for handling [netmap.NodeMutationAdd] and [netmap.NodeMutationRemove] instead.
func diffNodeViews(old, new []tailcfg.NodeView) (added, modified, removed []tailcfg.NodeView) {
	sortedByID := func(nodes []tailcfg.NodeView) []tailcfg.NodeView {
		ret := slices.Clone(nodes)
		slices.SortFunc(ret, func(a, b tailcfg.NodeView) int {
			return cmp.Compare(a.ID(), b.ID())
		})
		return ret
	}
	old = sortedByID(old)
	new = sortedByID(new)

	i, j := 0, 0
	for i < len(old) && j < len(new) {
		switch oid, nid := old[i].ID(), new[j].ID(); {
		case oid < nid:
			removed = append(removed, old[i])
			i++
		case oid > nid:
			added = append(added, new[j])
			j++
		case oid == nid:
			if !old[i].Equal(new[j]) {
				modified = append(modified, new[j])
			}
			i++
			j++
		}
	}
	removed = append(removed, old[i:]...)
	added = append(added, new[j:]...)
	return added, modified, removed
}
