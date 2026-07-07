// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"tailscale.com/health"
	"tailscale.com/types/key"
)

// SetExitNodePeer sets the peer that magicsock should treat as the current
// exit node for health monitoring. Pass a zero nodeKey to clear the
// exit-node association.
//
// displayName is used in the health warning text and may be empty.
//
// See [Conn.NoteExitNodeReachabilityResult] for how reachability results
// against this peer are surfaced as [health.ExitNodeUnreachableWarnable].
func (c *Conn) SetExitNodePeer(nodeKey key.NodePublic, displayName string) {
	var newKey *key.NodePublic
	if !nodeKey.IsZero() {
		k := nodeKey
		newKey = &k
	}
	old := c.exitNodeKey.Swap(newKey)

	c.mu.Lock()
	c.exitNodeName = displayName
	c.mu.Unlock()

	if sameExitNodeKey(old, newKey) {
		return
	}
	// The identity of the tracked peer changed (including transitions to or
	// from the zero key). Any warning we were carrying was about the old
	// peer, so clear it and let subsequent reachability results decide the
	// state of the new peer from scratch.
	if c.exitNodeUnhealthy.CompareAndSwap(true, false) {
		c.health.SetHealthy(health.ExitNodeUnreachableWarnable)
	}
}

func sameExitNodeKey(a, b *key.NodePublic) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}

// IsExitNodePeer reports whether k is the peer currently configured as the
// exit node (see [Conn.SetExitNodePeer]). It's safe to call from hot paths:
// the check is a single atomic-pointer load plus a NodePublic comparison,
// and does not acquire c.mu.
func (c *Conn) IsExitNodePeer(k key.NodePublic) bool {
	p := c.exitNodeKey.Load()
	return p != nil && *p == k
}

// NoteExitNodeReachabilityResult updates
// [health.ExitNodeUnreachableWarnable] based on a reachability outcome for
// peerKey. It is a no-op when peerKey is not the currently configured exit
// node peer.
//
// err == nil signals that peerKey was reached (e.g. a WireGuard packet
// arrived from the peer), causing the warning to clear. err != nil signals
// a reachability failure (e.g. magicsock could not deliver a WireGuard
// packet to the peer) and raises the warning; the [Warnable]'s
// TimeToVisible suppresses transient blips.
func (c *Conn) NoteExitNodeReachabilityResult(peerKey key.NodePublic, err error) {
	if err == nil && !c.exitNodeUnhealthy.Load() {
		return
	}
	k := c.exitNodeKey.Load()
	if k == nil || *k != peerKey {
		return
	}
	if err == nil {
		if c.exitNodeUnhealthy.CompareAndSwap(true, false) {
			c.health.SetHealthy(health.ExitNodeUnreachableWarnable)
		}
		return
	}
	if !c.exitNodeUnhealthy.CompareAndSwap(false, true) {
		return
	}
	c.mu.Lock()
	exitName := c.exitNodeName
	c.mu.Unlock()
	c.health.SetUnhealthy(health.ExitNodeUnreachableWarnable, health.Args{
		health.ArgExitNodeName: exitName,
		health.ArgError:        err.Error(),
	})
}
