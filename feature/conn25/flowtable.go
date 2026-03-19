// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"sync"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
)

// PacketAction may modify the packet.
type PacketAction func(*packet.Parsed)

// FlowData is an entry stored in the [FlowTable].
type FlowData struct {
	Tuple  flowtrack.Tuple
	Action PacketAction
}

// Origin is used to track the direction of a flow.
type Origin uint8

const (
	// FromTun indicates the flow is from the tun device.
	FromTun Origin = iota

	// FromWireGuard indicates the flow is from the WireGuard tunnel.
	FromWireGuard
)

type cachedFlow struct {
	flow   FlowData
	paired flowtrack.Tuple // tuple for the other direction
}

// FlowTable stores and retrieves [FlowData] that can be looked up
// by 5-tuple. New entries specify the tuple to use for both directions
// of traffic flow. The underlying cache is LRU, and the maximum number
// of entries is specified in calls to [NewFlowTable]. FlowTable has
// its own mutex and is safe for concurrent use.
type FlowTable struct {
	mu           sync.Mutex
	fromTunCache *flowtrack.Cache[cachedFlow] // guarded by mu
	fromWGCache  *flowtrack.Cache[cachedFlow] // guarded by mu
}

// NewFlowTable returns a [FlowTable] maxEntries maximum entries.
// A maxEntries of 0 indicates no maximum. See also [FlowTable].
func NewFlowTable(maxEntries int) *FlowTable {
	return &FlowTable{
		fromTunCache: &flowtrack.Cache[cachedFlow]{
			MaxEntries: maxEntries,
		},
		fromWGCache: &flowtrack.Cache[cachedFlow]{
			MaxEntries: maxEntries,
		},
	}
}

// LookupFromTunDevice looks up a [FlowData] entry that is valid to run for packets
// observed as coming from the tun device. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromTunDevice(k flowtrack.Tuple) (FlowData, bool) {
	return t.lookup(k, FromTun)
}

// LookupFromWireGuard looks up a [FlowData] entry that is valid to run for packets
// observed as coming from the WireGuard tunnel. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromWireGuard(k flowtrack.Tuple) (FlowData, bool) {
	return t.lookup(k, FromWireGuard)
}

func (t *FlowTable) lookup(k flowtrack.Tuple, want Origin) (FlowData, bool) {
	var cache *flowtrack.Cache[cachedFlow]
	switch want {
	case FromTun:
		cache = t.fromTunCache
	case FromWireGuard:
		cache = t.fromWGCache
	default:
		return FlowData{}, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	v, ok := cache.Get(k)
	if !ok {
		return FlowData{}, false
	}
	return v.flow, true
}

// NewFlowFromTunDevice installs (or overwrites) both the forward and return entries.
// The forward tuple is tagged as FromTun, and the return tuple is tagged as FromWireGuard.
// If overwriting, it removes the old paired tuple for the forward key to avoid stale reverse mappings.
func (t *FlowTable) NewFlowFromTunDevice(fwd, rev FlowData) error {
	return t.newFlow(FromTun, fwd, rev)
}

// NewFlowFromWireGuard installs (or overwrites) both the forward and return entries.
// The forward tuple is tagged as FromWireGuard, and the return tuple is tagged as FromTun.
// If overwriting, it removes the old paired tuple for the forward key to avoid stale reverse mappings.
func (t *FlowTable) NewFlowFromWireGuard(fwd, rev FlowData) error {
	return t.newFlow(FromWireGuard, fwd, rev)
}

func (t *FlowTable) newFlow(fwdOrigin Origin, fwd, rev FlowData) error {
	if fwd.Action == nil || rev.Action == nil {
		return errors.New("nil action received for flow")
	}

	var fwdCache, revCache *flowtrack.Cache[cachedFlow]
	switch fwdOrigin {
	case FromTun:
		fwdCache, revCache = t.fromTunCache, t.fromWGCache
	case FromWireGuard:
		fwdCache, revCache = t.fromWGCache, t.fromTunCache
	default:
		return errors.New("newFlow called with unknown direction")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// If overwriting an existing entry, remove its previously-paired mapping so
	// we don't leave stale tuples around.
	if old, ok := fwdCache.Get(fwd.Tuple); ok {
		revCache.Remove(old.paired)
	}
	if old, ok := revCache.Get(rev.Tuple); ok {
		fwdCache.Remove(old.paired)
	}

	fwdCache.Add(fwd.Tuple, cachedFlow{
		flow:   fwd,
		paired: rev.Tuple,
	})
	revCache.Add(rev.Tuple, cachedFlow{
		flow:   rev,
		paired: fwd.Tuple,
	})

	return nil
}
