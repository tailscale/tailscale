// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"container/list"
	"sync"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
)

// PacketAction may modify the packet.
type PacketAction func(*packet.Parsed)

// TupleAndAction wraps the [flowtrack.Tuple] and
// the [PacketAction] to return on lookups to that
// tuple.
type TupleAndAction struct {
	Tuple  flowtrack.Tuple
	Action PacketAction
}

// FlowData is an entry stored in the [FlowTable]
// constructed by the consumer of the table.
// It specifies tuples and actions for each direction
// of the flow.
type FlowData struct {
	FromTun TupleAndAction
	FromWG  TupleAndAction
}

// Origin is used to track the direction of a flow.
type Origin uint8

const (
	// FromTun indicates the flow is from the tun device.
	FromTun Origin = iota

	// FromWireGuard indicates the flow is from the WireGuard tunnel.
	FromWireGuard
)

// cachedFlow is the main unit of storage in the table.
// It wraps the [FlowData] passed in by the consumer, as well
// as internal metadata and callbacks.
type cachedFlow struct {
	data FlowData // user-defined tuples and actions for both directions

	// lastSeen time.Time // tracks when the flow was last hit for expiration management
	// onRemove func()    // fires on removal/expiration (e.g. update watchers, send RST to client)
}

// FlowTable stores and retrieves [FlowData] that can be looked up
// by 5-tuple [flowtrack.Tuple] and direction.
// New entries specify the tuple to use for both directions
// of traffic flow. The underlying cache is LRU, and the maximum number
// of entries is specified in calls to [NewFlowTable]. FlowTable has
// its own mutex and is safe for concurrent use.
type FlowTable struct {
	mu           sync.Mutex
	fromTunCache map[flowtrack.Tuple]*list.Element
	fromWGCache  map[flowtrack.Tuple]*list.Element
	lru          *list.List
	maxEntries   int
}

// NewFlowTable returns a [FlowTable] with maxEntries maximum entries.
// A maxEntries of 0 indicates no maximum. See also [FlowTable].
func NewFlowTable(maxEntries int) *FlowTable {
	return &FlowTable{
		fromTunCache: make(map[flowtrack.Tuple]*list.Element, maxEntries),
		fromWGCache:  make(map[flowtrack.Tuple]*list.Element, maxEntries),
		lru:          list.New(),
		maxEntries:   maxEntries,
	}
}

// LookupFromTunDevice looks up a [PacketAction] that is valid to run on packets
// observed as coming from the tun device. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromTunDevice(k flowtrack.Tuple) (PacketAction, bool) {
	return t.lookup(k, FromTun)
}

// LookupFromWireGuard looks up a [PacketAction] that is valid to run for packets
// observed as coming from the WireGuard tunnel. The tuple must match the direction it was
// stored with.
func (t *FlowTable) LookupFromWireGuard(k flowtrack.Tuple) (PacketAction, bool) {
	return t.lookup(k, FromWireGuard)
}

func (t *FlowTable) lookup(k flowtrack.Tuple, dir Origin) (PacketAction, bool) {
	var cache map[flowtrack.Tuple]*list.Element
	switch dir {
	case FromTun:
		cache = t.fromTunCache
	case FromWireGuard:
		cache = t.fromWGCache
	default:
		return nil, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	ele, ok := cache[k]
	if !ok {
		return nil, false
	}

	flow := ele.Value.(*cachedFlow)

	var action PacketAction
	switch dir {
	case FromTun:
		action = flow.data.FromTun.Action
	case FromWireGuard:
		action = flow.data.FromWG.Action
	}

	// Support LRU.
	t.lru.MoveToFront(ele)

	// TODO(mzb): Update flow.lastSeen.

	return action, true
}

// NewFlow installs data as an flow in the table, and evicts any flow that
// either tuple already points at. This can result in two flows being evicted
// if each of the new tuples point at distinct existing flows. If the new flow
// would cause the table to exceed its maximum size, the least recently used
// (looked-up or created) flow is evicted. data is not validated, the caller must
// supply non-nil packet actions.
func (t *FlowTable) NewFlow(data FlowData) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If either tuple leads to anything existing, remove it.
	t.removeFlowLocked(t.fromTunCache[data.FromTun.Tuple])
	t.removeFlowLocked(t.fromWGCache[data.FromWG.Tuple])

	flow := &cachedFlow{
		data: data,
		// Populate lastSeen
		// Populate onRemove()
	}

	ele := t.lru.PushFront(flow)
	if t.maxEntries > 0 && t.lru.Len() > t.maxEntries {
		t.removeFlowLocked(t.lru.Back())
	}

	t.fromTunCache[data.FromTun.Tuple] = ele
	t.fromWGCache[data.FromWG.Tuple] = ele

	return nil
}

func (t *FlowTable) removeFlowLocked(ele *list.Element) {
	if ele == nil {
		return
	}

	flow := t.lru.Remove(ele).(*cachedFlow)
	delete(t.fromTunCache, flow.data.FromTun.Tuple)
	delete(t.fromWGCache, flow.data.FromWG.Tuple)

	// TODO(mzb): run flow.onRemove()
}
