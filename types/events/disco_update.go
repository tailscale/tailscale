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
