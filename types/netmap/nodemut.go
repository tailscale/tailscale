// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmap

import (
	"cmp"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"tailscale.com/tailcfg"
)

// NodeMutation is the common interface for types that describe
// the change of a node's state.
type NodeMutation interface {
	NodeIDBeingMutated() tailcfg.NodeID
	Apply(*tailcfg.Node)
}

type mutatingNodeID tailcfg.NodeID

func (m mutatingNodeID) NodeIDBeingMutated() tailcfg.NodeID { return tailcfg.NodeID(m) }

// NodeMutationDERPHome is a NodeMutation that says a node
// has changed its DERP home region.
type NodeMutationDERPHome struct {
	mutatingNodeID
	DERPRegion int
}

func (m NodeMutationDERPHome) Apply(n *tailcfg.Node) {
	n.HomeDERP = m.DERPRegion
}

// NodeMutationEndpoints is a NodeMutation that says a node's endpoints have changed.
type NodeMutationEndpoints struct {
	mutatingNodeID
	Endpoints []netip.AddrPort
}

func (m NodeMutationEndpoints) Apply(n *tailcfg.Node) {
	n.Endpoints = slices.Clone(m.Endpoints)
}

// NodeMutationOnline is a NodeMutation that says a node is now online or
// offline.
type NodeMutationOnline struct {
	mutatingNodeID
	Online bool
}

func (m NodeMutationOnline) Apply(n *tailcfg.Node) {
	n.Online = new(m.Online)
}

// NodeMutationLastSeen is a NodeMutation that says a node's LastSeen
// value should be set to the current time.
type NodeMutationLastSeen struct {
	mutatingNodeID
	LastSeen time.Time
}

func (m NodeMutationLastSeen) Apply(n *tailcfg.Node) {
	n.LastSeen = new(m.LastSeen)
}

// NodeMutationUpsert is a NodeMutation that says a peer's full Node value
// should be inserted or replaced.
//
// Apply is a no-op: consumers of NodeMutationUpsert must type-switch to handle
// upserts by storing Node in their peer map.
type NodeMutationUpsert struct {
	Node tailcfg.NodeView
}

func (m NodeMutationUpsert) NodeIDBeingMutated() tailcfg.NodeID { return m.Node.ID() }
func (m NodeMutationUpsert) Apply(*tailcfg.Node)                {}

// NodeMutationRemove is a NodeMutation that says a peer has been removed.
// Apply is a no-op: consumers of NodeMutationRemove must type-switch to handle
// removes by deleting the node from their peer map.
type NodeMutationRemove struct {
	mutatingNodeID
}

func (m NodeMutationRemove) Apply(*tailcfg.Node) {}

var peerChangeFields = sync.OnceValue(func() []reflect.StructField {
	var fields []reflect.StructField
	rt := reflect.TypeFor[tailcfg.PeerChange]()
	for field := range rt.Fields() {
		fields = append(fields, field)
	}
	return fields
})

// NodeMutationsFromPatch returns the NodeMutations that
// p describes. If p describes something not yet supported
// by a specific NodeMutation type, it returns (nil, false).
func NodeMutationsFromPatch(p *tailcfg.PeerChange) (_ []NodeMutation, ok bool) {
	if p == nil || p.NodeID == 0 {
		return nil, false
	}
	var ret []NodeMutation
	rv := reflect.ValueOf(p).Elem()
	for i, sf := range peerChangeFields() {
		if rv.Field(i).IsZero() {
			continue
		}
		switch sf.Name {
		default:
			// Unhandled field.
			return nil, false
		case "NodeID":
			continue
		case "DERPRegion":
			ret = append(ret, NodeMutationDERPHome{mutatingNodeID(p.NodeID), p.DERPRegion})
		case "Endpoints":
			ret = append(ret, NodeMutationEndpoints{mutatingNodeID(p.NodeID), slices.Clone(p.Endpoints)})
		case "Online":
			ret = append(ret, NodeMutationOnline{mutatingNodeID(p.NodeID), *p.Online})
		case "LastSeen":
			ret = append(ret, NodeMutationLastSeen{mutatingNodeID(p.NodeID), *p.LastSeen})
		}
	}
	return ret, true
}

// MutationsFromMapResponse returns all the discrete node mutations described
// by res. It returns ok=false if res contains any non-delta field as defined
// by mapResponseContainsNonPatchFields.
//
// Upserts and removes (from res.PeersChanged / res.PeersRemoved) are emitted
// as NodeMutationUpsert / NodeMutationRemove entries. A PeersChanged entry can
// be either a new peer or a full replacement for an existing peer that couldn't
// be represented as PeerChangedPatch. Callers must type-switch to handle those
// alongside field mutations.
func MutationsFromMapResponse(res *tailcfg.MapResponse, now time.Time) (ret []NodeMutation, ok bool) {
	if now.IsZero() {
		now = time.Now()
	}
	if mapResponseContainsNonPatchFields(res) {
		return nil, false
	}

	for _, id := range res.PeersRemoved {
		ret = append(ret, NodeMutationRemove{mutatingNodeID(id)})
	}
	for _, n := range res.PeersChanged {
		// Any n still in PeersChanged after patchifyPeersChanged is a
		// truly-new (or replaced) peer.
		ret = append(ret, NodeMutationUpsert{Node: n.View()})
	}
	for _, p := range res.PeersChangedPatch {
		deltas, ok := NodeMutationsFromPatch(p)
		if !ok {
			return nil, false
		}
		ret = append(ret, deltas...)
	}
	for nid, v := range res.OnlineChange {
		ret = append(ret, NodeMutationOnline{mutatingNodeID(nid), v})
	}
	for nid, v := range res.PeerSeenChange {
		if v {
			ret = append(ret, NodeMutationLastSeen{mutatingNodeID(nid), now})
		}
	}
	slices.SortStableFunc(ret, func(a, b NodeMutation) int {
		return cmp.Compare(a.NodeIDBeingMutated(), b.NodeIDBeingMutated())
	})
	return ret, true
}

// mapResponseContainsNonPatchFields reports whether res contains any field
// that can't be expressed as a per-peer NodeMutation (including the new
// NodeMutationUpsert / NodeMutationRemove variants) or via the sibling narrow
// setter methods on the map-session backend (e.g. UpdatePacketFilter).
//
// When this returns true, the caller must fall back to rebuilding and
// dispatching a full NetworkMap. When it returns false, the response can be
// handled incrementally.
//
// PeersChanged, PeersRemoved, and PacketFilter(s) are intentionally not in
// this list: upserted/removed peers ride NodeMutationUpsert/Remove, packet
// filter updates are delivered via the backend's UpdatePacketFilter
// method, and UserProfile updates ride the backend's UpdateUserProfiles
// method.
func mapResponseContainsNonPatchFields(res *tailcfg.MapResponse) bool {
	return res.Node != nil ||
		res.DERPMap != nil ||
		res.DNSConfig != nil ||
		res.Domain != "" ||
		res.CollectServices != "" ||
		res.Health != nil ||
		res.DisplayMessages != nil ||
		res.SSHPolicy != nil ||
		res.TKAInfo != nil ||
		res.DomainDataPlaneAuditLogID != "" ||
		res.Debug != nil ||
		res.ControlDialPlan != nil ||
		res.ClientVersion != nil ||
		res.Peers != nil ||
		res.DeprecatedDefaultAutoUpdate != ""
}
