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
	allow  Origin          // which lookup is allowed to hit this entry
}

var (
	ErrFlowNotFound = errors.New("flow not found")
)

// FlowTable stores and retrieves [FlowData] that can be looked up
// by 5-tuple. New entries specify the tuple to use for both directions
// of traffic flow. The underlying cache is LRU, and the maximum number
// of entries is specified in calls to [NewFlowTable]. FlowTable has
// its own mutex and is safe for concurrent use.
type FlowTable struct {
	mu  sync.Mutex
	lru flowtrack.Cache[cachedFlow] // guarded by mu
}

// NewFlowTable returns a [FlowTable] maxEntries maximum entries.
// A maxEntries of 0 indicates no maximum. See also [FlowTable].
func NewFlowTable(maxEntries int) *FlowTable {
	t := &FlowTable{}
	t.lru.MaxEntries = maxEntries
	return t
}

func opposite(o Origin) Origin {
	if o == FromTun {
		return FromWireGuard
	}
	return FromTun
}

// LookupFromTunDevice looks up a [FlowData] entry that is valid to run for packets
// observed as coming from the tun device. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromTunDevice(k flowtrack.Tuple) (FlowData, error) {
	return t.lookup(k, FromTun)
}

// LookupFromWireGuard looks up a [FlowData] entry that is valid to run for packets
// observed as coming from the WireGuard tunnel. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromWireGuard(k flowtrack.Tuple) (FlowData, error) {
	return t.lookup(k, FromWireGuard)
}

func (t *FlowTable) lookup(k flowtrack.Tuple, want Origin) (FlowData, error) {
	t.mu.Lock()
	v, ok := t.lru.Get(k)
	if !ok || v.allow != want {
		t.mu.Unlock()
		return FlowData{}, ErrFlowNotFound
	}
	out := v.flow // copy
	t.mu.Unlock()
	return out, nil
}

// NewFlowFromTunDevice installs (or overwrites) both the forward and return entries.
// The forward tuple is tagged as FromTun, and the return tuple is tagged as FromWireGuard.
// If overwriting, it removes the old paired tuple for the forward key to avoid stale reverse mappings.
func (t *FlowTable) NewFlowFromTunDevice(fwd, ret FlowData) error {
	return t.newFlow(FromTun, fwd, ret)
}

// NewFlowFromWireGuard installs (or overwrites) both the forward and return entries.
// The forward tuple is tagged as FromWireGuard, and the return tuple is tagged as FromTun.
// If overwriting, it removes the old paired tuple for the forward key to avoid stale reverse mappings.
func (t *FlowTable) NewFlowFromWireGuard(fwd, ret FlowData) error {
	return t.newFlow(FromWireGuard, fwd, ret)
}

func (t *FlowTable) newFlow(primaryAllow Origin, fwd, ret FlowData) error {
	if fwd.Action == nil || ret.Action == nil {
		return errors.New("nil action received for flow")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// If overwriting an existing primary entry, remove its previously-paired mapping so
	// we don't leave stale reverse tuples around.
	if old, ok := t.lru.Get(fwd.Tuple); ok {
		t.lru.Remove(old.paired)
	}

	t.lru.Add(fwd.Tuple, cachedFlow{
		flow:   fwd,
		paired: ret.Tuple,
		allow:  primaryAllow,
	})
	t.lru.Add(ret.Tuple, cachedFlow{
		flow:   ret,
		paired: fwd.Tuple,
		allow:  opposite(primaryAllow),
	})

	return nil
}
