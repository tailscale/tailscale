// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package topics defines event types used with the eventbus.
package topics

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// DERPConnChange is published when the set of DERP connections changes.
type DERPConnChange struct {
	RegionID  int  // DERP region ID
	Connected bool // true for connected, false for disconnected
	LiveDERPs int  // total number of live DERP connections after this change
}

// EndpointsChanged is published when magicsock's endpoints change.
type EndpointsChanged []tailcfg.Endpoint

// TUNStatusChange is published when the TUN device goes up or down.
type TUNStatusChange struct {
	Up bool // true if TUN is up, false if down
}

// PeerRecvActivity is published periodically when a packet is received from a peer.
// This is called no more than once every 10 seconds per peer.
type PeerRecvActivity struct {
	PeerKey key.NodePublic
}
