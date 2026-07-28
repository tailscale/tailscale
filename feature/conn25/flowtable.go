// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"container/list"
	"context"
	"sync"
	"time"

	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/tstime/mono"
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

	// OnRemove, if non-nil, is invoked when the flow is removed from the
	// table for any reason (idle expiration, tuple-collision displacement
	// in [FlowTable.NewFlow], or capacity eviction). It is called once,
	// outside the table's mutex, so it may safely acquire other locks.
	OnRemove func()
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

	lastSeen mono.Time // tracks when the flow was last hit for expiration management
}

// FlowTable stores and retrieves [FlowData] that can be looked up
// by 5-tuple [flowtrack.Tuple] and direction.
// New entries specify the tuple to use for both directions
// of traffic flow. The underlying cache is LRU, and the maximum number
// of entries is specified in calls to [NewFlowTable]. FlowTable has
// its own mutex and is safe for concurrent use.
type FlowTable struct {
	maxEntries         int
	idleTimeout        time.Duration
	sweepInterval      time.Duration
	maxRemovedPerSweep int

	mu           sync.Mutex
	fromTunCache map[flowtrack.Tuple]*list.Element
	fromWGCache  map[flowtrack.Tuple]*list.Element
	lru          *list.List
}

const (
	// DefaultFlowIdleTimeout is the default idle timeout for a flow.
	// See also [WithFlowIdleTimeout].
	DefaultFlowIdleTimeout = 5 * time.Minute
	// DefaultFlowSweepInterval is the default sweep interval for
	// automatically removing expired flows. See also [WithFlowSweepInterval].
	DefaultFlowSweepInterval = 3 * time.Minute
	// DefaultMaxRemovedFlowsPerSweep is the default maximum number of
	// flows removed per sweep. It can be used to tune how long the table
	// mutex is held during sweeps. See also [WithMaxRemovedFlowsPerSweep].
	DefaultMaxRemovedFlowsPerSweep = 1000
)

// FlowTableOption configures options for use with [NewFlowTable].
type FlowTableOption func(ft *FlowTable)

// WithFlowIdleTimeout sets the threshold duration for flow idle time
// before it is eligible for removal. A flow is considered idle for the
// time that elapses since its creation or last lookup. A duration of
// 0 means that expiration is disabled. If WithFlowIdleTimeout is not
// passed to [NewFlowTable], then [DefaultFlowIdleTimeout] is used.
func WithFlowIdleTimeout(timeout time.Duration) FlowTableOption {
	return func(ft *FlowTable) {
		ft.idleTimeout = timeout
	}
}

// WithFlowSweepInterval sets the interval to automatically
// remove idle flows that exceed the idle timeout. A value of 0
// disables automatic sweeping. If WithFlowSweepInterval is not
// passed to [NewFlowTable], then [DefaultFlowSweepInterval] is used.
func WithFlowSweepInterval(ival time.Duration) FlowTableOption {
	return func(ft *FlowTable) {
		ft.sweepInterval = ival
	}
}

// WithMaxRemovedFlowsPerSweep sets maximum number of expired
// flows that can be removed per sweep. A value of 0 means no
// maximum. If WithMaxRemovedFlowsPerSweep is not passed to
// [NewFlowTable], then [DefaultMaxRemovedFlowsPerSweep] is used.
func WithMaxRemovedFlowsPerSweep(maxPer int) FlowTableOption {
	return func(ft *FlowTable) {
		ft.maxRemovedPerSweep = maxPer
	}
}

// NewFlowTable returns a [FlowTable] with maxEntries maximum entries.
// A maxEntries of 0 indicates no maximum. See also [FlowTable].
func NewFlowTable(maxEntries int, opts ...FlowTableOption) *FlowTable {
	ft := &FlowTable{
		maxEntries:         maxEntries,
		idleTimeout:        DefaultFlowIdleTimeout,
		sweepInterval:      DefaultFlowSweepInterval,
		maxRemovedPerSweep: DefaultMaxRemovedFlowsPerSweep,
		fromTunCache:       make(map[flowtrack.Tuple]*list.Element, maxEntries),
		fromWGCache:        make(map[flowtrack.Tuple]*list.Element, maxEntries),
		lru:                list.New(),
	}

	for _, o := range opts {
		o(ft)
	}
	return ft
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

	flow.lastSeen = mono.Now()

	return action, true
}

// NewFlow installs data as an flow in the table, and evicts any flow that
// either tuple already points at. This can result in two flows being evicted
// if each of the new tuples point at distinct existing flows. If the new flow
// would cause the table to exceed its maximum size, the least recently used
// (looked-up or created) flow is evicted. data is not validated, the caller must
// supply non-nil packet actions.
//
// Any [FlowData.OnRemove] callbacks belonging to displaced or evicted flows are
// invoked after the table's mutex is released, before NewFlow returns.
func (t *FlowTable) NewFlow(data FlowData) {
	var onRemoves []func()

	t.mu.Lock()
	// If either tuple leads to anything existing, remove it.
	onRemoves = append(onRemoves, t.removeFlowLocked(t.fromTunCache[data.FromTun.Tuple]))
	onRemoves = append(onRemoves, t.removeFlowLocked(t.fromWGCache[data.FromWG.Tuple]))

	flow := &cachedFlow{
		data:     data,
		lastSeen: mono.Now(),
	}

	ele := t.lru.PushFront(flow)
	if t.maxEntries > 0 && t.lru.Len() > t.maxEntries {
		onRemoves = append(onRemoves, t.removeFlowLocked(t.lru.Back()))
	}

	t.fromTunCache[data.FromTun.Tuple] = ele
	t.fromWGCache[data.FromWG.Tuple] = ele
	t.mu.Unlock()

	for _, onRemove := range onRemoves {
		if onRemove != nil {
			onRemove()
		}
	}
}

// StartExpiredSweeper starts a sweeper that removes idle flows that have
// not been created or looked up for a duration greater than the configured
// idle timeout. See [WithFlowIdleTimeout]. The sweep runs at the configured
// sweep interval. See [WithFlowSweepInterval]. The sweeper stops when ctx
// is canceled.
func (t *FlowTable) StartExpiredSweeper(ctx context.Context) {
	if t.sweepInterval == 0 || t.idleTimeout == 0 {
		return
	}

	ticker := time.NewTicker(t.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.removeIdle(mono.Now())
		}
	}
}

func (t *FlowTable) removeIdle(now mono.Time) int {
	if t.idleTimeout == 0 {
		return 0
	}

	var onRemoves []func()
	t.mu.Lock()

	removed := 0
	for ele := t.lru.Back(); ele != nil; ele = t.lru.Back() {
		if t.maxRemovedPerSweep > 0 && removed >= t.maxRemovedPerSweep {
			break
		}
		flow := ele.Value.(*cachedFlow)
		if now.Sub(flow.lastSeen) <= t.idleTimeout {
			break
		}
		onRemoves = append(onRemoves, t.removeFlowLocked(ele))
		removed++
	}
	t.mu.Unlock()

	for _, onRemove := range onRemoves {
		if onRemove != nil {
			onRemove()
		}
	}

	return removed
}

// removeFlowLocked detaches the flow at ele from t, and returns the flow's
// [FlowData.OnRemove] callback, which may be nil. The caller must hold the
// mutex while calling removeFlowLocked, and release it before invoking the
// callback.
func (t *FlowTable) removeFlowLocked(ele *list.Element) func() {
	if ele == nil {
		return nil
	}

	flow := t.lru.Remove(ele).(*cachedFlow)
	delete(t.fromTunCache, flow.data.FromTun.Tuple)
	delete(t.fromWGCache, flow.data.FromWG.Tuple)

	return flow.data.OnRemove
}
