// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package guivisibility interprets the HiddenNetworkDevices policy for IPN
// bus watchers and populates [ipn.Notify.NodeGUIVisibility] accordingly.
package guivisibility

import (
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

func init() {
	if feature.Register("guivisibility") {
		ipnext.RegisterExtension("guivisibility", newExtension)
	}
}

func newExtension(logger.Logf, ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{}, nil
}

type extension struct {
	host ipnext.Host
}

func (e *extension) Name() string { return "guivisibility" }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().MutateNotifyForSessionLocked.Add(e.mutateNotifyForSession)
	return nil
}

func (e *extension) Shutdown() error { return nil }

// mutateNotifyForSession populates n.NodeGUIVisibility with the peers that
// sess's HiddenNetworkDevices policy hides: all of them if n carries a policy
// snapshot, or those among n.PeersChanged otherwise.
func (e *extension) mutateNotifyForSession(sess ipnext.WatchSession, n *ipn.Notify) {
	if n.Policy == nil && len(n.PeersChanged) == 0 {
		return
	}
	hidden := hiddenNetworkDevicesFromPolicy(sess.Policy())
	if hidden == (hiddenNetworkDevices{}) {
		return
	}
	nb := e.host.NodeBackend()
	self := nb.Self()
	if !self.Valid() {
		return
	}
	var visibility map[tailcfg.StableNodeID]ipn.NodeGUIVisibility
	hide := func(peer tailcfg.NodeView) {
		if peerHiddenInGUI(peer, self, hidden) {
			mak.Set(&visibility, peer.StableID(), ipn.NodeGUIVisibility{HideInGUI: true})
		}
	}
	if n.Policy != nil {
		for _, peer := range nb.Peers() {
			hide(peer)
		}
	} else {
		for _, peer := range n.PeersChanged {
			hide(peer.View())
		}
	}
	n.NodeGUIVisibility = visibility
}

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
