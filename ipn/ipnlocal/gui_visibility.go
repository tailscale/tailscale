// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

const (
	hiddenNetworkDevicesCurrentUser   = "current-user"
	hiddenNetworkDevicesOtherUsers    = "other-users"
	hiddenNetworkDevicesTaggedDevices = "tagged-devices"
)

// hiddenNetworkDevices is the parsed HiddenNetworkDevices policy for a watch
// session. Its zero value means no devices are hidden.
type hiddenNetworkDevices struct {
	currentUser   bool
	otherUsers    bool
	taggedDevices bool
}

func hiddenNetworkDevicesFromPolicy(snapshot *policyclient.PolicySnapshot) hiddenNetworkDevices {
	values := policyclient.GetStringArrayFromSnapshot(
		snapshot,
		pkey.HiddenNetworkDevices,
	)

	var hidden hiddenNetworkDevices
	for _, value := range values {
		switch value {
		case hiddenNetworkDevicesCurrentUser:
			hidden.currentUser = true
		case hiddenNetworkDevicesOtherUsers:
			hidden.otherUsers = true
		case hiddenNetworkDevicesTaggedDevices:
			hidden.taggedDevices = true
		}
	}
	return hidden
}

// nodeGUIVisibilityLocked returns a complete snapshot of GUI visibility
// metadata for self and all current peers.
//
// b.mu must be held.
func (b *LocalBackend) nodeGUIVisibilityLocked(hidden hiddenNetworkDevices) map[tailcfg.StableNodeID]ipn.NodeGUIVisibility {
	cn := b.currentNode()
	nm := cn.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return nil
	}

	visibility := make(map[tailcfg.StableNodeID]ipn.NodeGUIVisibility, len(nm.Peers)+1)

	visibility[nm.SelfNode.StableID()] = ipn.NodeGUIVisibility{}

	for _, peer := range nm.Peers {
		visibility[peer.StableID()] = ipn.NodeGUIVisibility{
			HideInGUI: peerHiddenInGUI(peer, nm.SelfNode, hidden),
		}
	}

	return visibility
}

func peerHiddenInGUI(peer, self tailcfg.NodeView, hidden hiddenNetworkDevices) bool {
	if peer.ID() == self.ID() {
		return false
	}

	if peer.IsTagged() {
		return hidden.taggedDevices
	}

	if peer.SharerOrUser() == self.User() {
		return hidden.currentUser
	}

	return hidden.otherUsers
}
