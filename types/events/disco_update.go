// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package events defines types for working with events.
package events

import (
	"net/netip"

	"tailscale.com/types/key"
)

// DiscoKeyAdvertisement is a TSMP message used for distributing disco keys.
// This struct is used an an event on the [eventbus.Bus].
type DiscoKeyAdvertisement struct {
	Src netip.Addr // Src field is populated by the IP header of the packet, not from the payload itself.
	Key key.DiscoPublic
}

// PeerDiscoKeyUpdate is a mirror implementation of DiscoKeyAdvertisement.
// It exists like this to be able to have a possible chain of the same event
// between different modules, specifically to update the peer directly without
// going through the chain of a mapSession that is only available in some
// instances.
type PeerDiscoKeyUpdate DiscoKeyAdvertisement
