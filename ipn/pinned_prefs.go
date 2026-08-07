// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"slices"

	"tailscale.com/tailcfg"
)

// PinnedPrefs holds the user's locally-pinned favorites, grouped by category. Pins are per-device,
// not synced across a user's devices, and stored under the "pinned" prefs for the current profile.
type PinnedPrefs struct {
	Devices   []PinnedItem `json:",omitzero"`
	ExitNodes []PinnedItem `json:",omitzero"`
	Services  []PinnedItem `json:",omitzero"`
}

// PinnedItem identifies a single pinned item: a device or exit node by ID, or a service by Service.
type PinnedItem struct {
	ID      tailcfg.StableNodeID `json:",omitzero"`
	Service tailcfg.ServiceName  `json:",omitzero"`
}

// Key returns whichever identifier is set. It's unique within a category.
func (it PinnedItem) Key() string {
	if it.Service != "" {
		return string(it.Service)
	}
	return string(it.ID)
}

// Equals reports whether a and b hold the same pins in the same order. Order is significant: it's
// the user's display order, so a reorder is a real change.
func (a PinnedPrefs) Equals(b PinnedPrefs) bool {
	return slices.Equal(a.Devices, b.Devices) &&
		slices.Equal(a.ExitNodes, b.ExitNodes) &&
		slices.Equal(a.Services, b.Services)
}

// PinnedPrefsRequest is the body POSTed to /prefs/pinned. Only categories whose Set field is true
// are replaced, so a client can update one without clobbering the rest in a read-modify-write race.
type PinnedPrefsRequest struct {
	Pinned       PinnedPrefs
	DevicesSet   bool `json:",omitzero"`
	ExitNodesSet bool `json:",omitzero"`
	ServicesSet  bool `json:",omitzero"`
}
