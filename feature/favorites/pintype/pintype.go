// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package pintype holds the types for locally-pinned favorites (devices, exit nodes, and services).
// They're shared by the favorites feature and the LocalAPI client.
package pintype

import (
	"slices"

	"tailscale.com/tailcfg"
)

// Set holds the user's locally-pinned favorites, grouped by category. Pins are per-device, not
// synced across a user's devices, and stored under the "favorites" feature for the current profile.
type Set struct {
	Devices   []Device   `json:",omitzero"`
	ExitNodes []ExitNode `json:",omitzero"`
	Services  []Service  `json:",omitzero"`
}

// Device is a pinned device, identified by its stable node ID.
type Device struct {
	ID tailcfg.StableNodeID `json:",omitzero"`
}

// ExitNode is a pinned exit node, identified by its stable node ID.
type ExitNode struct {
	ID tailcfg.StableNodeID `json:",omitzero"`
}

// Service is a pinned service, identified by its name.
type Service struct {
	Name tailcfg.ServiceName `json:",omitzero"`
}

// Key returns an opaque identifier for d, only comparable against other Device Keys. It may change
// across client versions, so don't persist it.
func (d Device) Key() string { return string(d.ID) }

// Key returns an opaque identifier for n, only comparable against other ExitNode Keys. It may change
// across client versions, so don't persist it.
func (n ExitNode) Key() string { return string(n.ID) }

// Key returns an opaque identifier for s, only comparable against other Service Keys. It may change
// across client versions, so don't persist it.
func (s Service) Key() string { return string(s.Name) }

// Equals reports whether a and b hold the same pins in the same order. Order is significant: it's
// the user's display order, so a reorder is a real change.
func (a Set) Equals(b Set) bool {
	return slices.Equal(a.Devices, b.Devices) &&
		slices.Equal(a.ExitNodes, b.ExitNodes) &&
		slices.Equal(a.Services, b.Services)
}

// SetRequest is the body POSTed to /pins. Only categories whose Set field is true are replaced, so
// a client can update one without clobbering the rest in a read-modify-write race.
type SetRequest struct {
	Pins         Set
	DevicesSet   bool `json:",omitzero"`
	ExitNodesSet bool `json:",omitzero"`
	ServicesSet  bool `json:",omitzero"`
}
