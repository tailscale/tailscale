// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package events contains type used as eventbus topics in tailscaled.
package events

import (
	"net/netip"

	"tailscale.com/types/key"
)

// DiscoKeyAdvertisement is an event sent on the [eventbus.Bus] when a disco
// key has been received over TSMP.
//
// Its publisher is [tstun.Wrapper]; its main subscriber is
// [controlclient.Direct], that injects the received key into the netmap as if
// it was a netmap update from control.
type DiscoKeyAdvertisement struct {
	Src netip.Addr // Src field is populated by the IP header of the packet, not from the payload itself.
	Key key.DiscoPublic
}

// PeerDiscoKeyUpdate is an event sent on the [eventbus.Bus] when
// [controlclient.Direct] deems that it cannot handle the key update.
//
// Its publisher is [controlclient.Direct]; its main subscriber is
// [wgengine.userspaceengine], that injects the received key into its
// [magicsock.Conn] in order to set up the key directly.
type PeerDiscoKeyUpdate DiscoKeyAdvertisement
