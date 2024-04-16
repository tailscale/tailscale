// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmap

import (
	"cmp"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
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
	n.DERP = fmt.Sprintf("127.3.3.40:%v", m.DERPRegion)
}

// NodeMutation is a NodeMutation that says a node's endpoints have changed.
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
	n.Online = ptr.To(m.Online)
}

// NodeMutationLastSeen is a NodeMutation that says a node's LastSeen
// value should be set to the current time.
type NodeMutationLastSeen struct {
	mutatingNodeID
	LastSeen time.Time
}

func (m NodeMutationLastSeen) Apply(n *tailcfg.Node) {
	n.LastSeen = ptr.To(m.LastSeen)
}

var peerChangeFields = sync.OnceValue(func() []reflect.StructField {
	var fields []reflect.StructField
	rt := reflect.TypeFor[tailcfg.PeerChange]()
	for i := range rt.NumField() {
		fields = append(fields, rt.Field(i))
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
// by res. It returns ok=false if res contains any non-patch field as defined
// by mapResponseContainsNonPatchFields.
func MutationsFromMapResponse(res *tailcfg.MapResponse, now time.Time) (ret []NodeMutation, ok bool) {
	if now.IsZero() {
		now = time.Now()
	}
	if mapResponseContainsNonPatchFields(res) {
		return nil, false
	}
	// All that remains is PeersChangedPatch, OnlineChange, and LastSeenChange.

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

// mapResponseContainsNonPatchFields reports whether res contains only "patch"
// fields set (PeersChangedPatch primarily, but also including the legacy
// PeerSeenChange and OnlineChange fields).
//
// It ignores any of the meta fields that are handled by PollNetMap before the
// peer change handling gets involved.
//
// The purpose of this function is to ask whether this is a tricky enough
// MapResponse to warrant a full netmap update. When this returns false, it
// means the response can be handled incrementally, patching up the local state.
func mapResponseContainsNonPatchFields(res *tailcfg.MapResponse) bool {
	return res.Node != nil ||
		res.DERPMap != nil ||
		res.DNSConfig != nil ||
		res.Domain != "" ||
		res.CollectServices != "" ||
		res.PacketFilter != nil ||
		res.PacketFilters != nil ||
		res.UserProfiles != nil ||
		res.Health != nil ||
		res.SSHPolicy != nil ||
		res.TKAInfo != nil ||
		res.DomainDataPlaneAuditLogID != "" ||
		res.Debug != nil ||
		res.ControlDialPlan != nil ||
		res.ClientVersion != nil ||
		res.Peers != nil ||
		res.PeersRemoved != nil ||
		// PeersChanged is too coarse to be considered a patch. Also, we convert
		// PeersChanged to PeersChangedPatch in patchifyPeersChanged before this
		// function is called, so it should never be set anyway. But for
		// completedness, and for tests, check it too:
		res.PeersChanged != nil ||
		res.DefaultAutoUpdate != "" ||
		res.MaxKeyDuration > 0
}
