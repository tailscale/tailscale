// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/util/syspolicy/policyclient"
)

// guiVisibilityFilterLocked gets the optional GUI-specific extension.
// b.mu must be held.
func (b *LocalBackend) guiVisibilityFilterLocked(snapshot *policyclient.PolicySnapshot) ipnext.GUIVisibilityFilter {
	var provider ipnext.GUIVisibilityProvider
	if !b.FindMatchingExtension(&provider) {
		return nil
	}
	return provider.ForPolicy(snapshot)
}

// nodeGUIVisibilityLocked returns a snapshot of hidden peers. An empty,
// non-nil map clears the previous snapshot when the policy is disabled.
// b.mu must be held.
func (b *LocalBackend) nodeGUIVisibilityLocked(filter ipnext.GUIVisibilityFilter) (map[tailcfg.StableNodeID]ipn.NodeGUIVisibility, map[tailcfg.NodeID]tailcfg.StableNodeID) {
	visibility := make(map[tailcfg.StableNodeID]ipn.NodeGUIVisibility)
	if filter == nil {
		return visibility, nil
	}
	nm := b.currentNode().NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return visibility, nil
	}
	var hidden map[tailcfg.NodeID]tailcfg.StableNodeID
	for _, peer := range nm.Peers {
		if filter.Hide(peer, nm.SelfNode) {
			visibility[peer.StableID()] = ipn.NodeGUIVisibility{HideInGUI: true}
			mak.Set(&hidden, peer.ID(), peer.StableID())
		}
	}
	return visibility, hidden
}

// nodeGUIVisibilityDeltaLocked evaluates only peers in this notification.
// It returns nil deltas if effective visibility did not change.
// b.mu must be held.
func (b *LocalBackend) nodeGUIVisibilityDeltaLocked(sess *watchSession, n *ipn.Notify) (map[tailcfg.StableNodeID]ipn.NodeGUIVisibility, []tailcfg.StableNodeID) {
	var changes map[tailcfg.StableNodeID]ipn.NodeGUIVisibility
	var removed []tailcfg.StableNodeID
	nm := b.currentNode().NetMap()
	var self tailcfg.NodeView
	if nm != nil {
		self = nm.SelfNode
	}
	for _, id := range n.PeersRemoved {
		if stable, ok := sess.hiddenPeers[id]; ok {
			removed = append(removed, stable)
			delete(sess.hiddenPeers, id)
		}
	}
	for _, peer := range n.PeersChanged {
		if peer == nil {
			continue
		}
		if prev, ok := sess.hiddenPeers[peer.ID]; ok && prev != peer.StableID {
			removed = append(removed, prev)
			delete(sess.hiddenPeers, peer.ID)
		}
		hidden := self.Valid() && sess.guiVisibility.Hide(peer.View(), self)
		_, wasHidden := sess.hiddenPeers[peer.ID]
		if hidden == wasHidden {
			continue
		}
		if hidden {
			mak.Set(&changes, peer.StableID, ipn.NodeGUIVisibility{HideInGUI: true})
			mak.Set(&sess.hiddenPeers, peer.ID, peer.StableID)
		} else {
			removed = append(removed, peer.StableID)
			delete(sess.hiddenPeers, peer.ID)
		}
	}
	return changes, removed
}
