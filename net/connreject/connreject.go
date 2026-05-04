// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package connreject provides a bounded, in-memory, per-direction
// aggregator of recent connection-rejection events observed by the
// local node.
//
// A rejection event is any evidence that a connection attempt was
// blocked or dropped: a peer's TSMP reject message, an outbound TSMP
// reject we emitted because a peer's inbound connection violated our
// ACLs, a pendopen timeout where we never saw a reply, etc.
//
// The aggregator is split by [Direction]:
//   - [Outgoing]: connections initiated by this node that were rejected
//     or otherwise failed (keyed on the peer's address — "who we failed
//     to reach").
//   - [Incoming]: connections from a peer that this node rejected
//     (keyed on the peer's address — "who we blocked").
//
// Repeated observations for the same (direction, proto, peer-address,
// reason) are aggregated into a single [Event], bumping Count and Last.
// LRU-by-count eviction keeps each direction's buffer bounded.
//
// This package contains only the data types and aggregator implementation;
// wiring into the rest of the system is done by feature/connreject.
package connreject

import (
	"container/list"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/types/ipproto"
)

// Direction describes whether a rejection applied to a connection this
// node initiated (Outgoing) or a connection a peer initiated toward us
// (Incoming).
//
// Direction is a string type so it serializes directly to human-readable
// JSON without requiring MarshalText/UnmarshalText boilerplate.
type Direction string

// Direction values.
const (
	DirectionUnknown Direction = ""
	Outgoing         Direction = "outgoing"
	Incoming         Direction = "incoming"
)

// Source describes how this node learned of a rejection.
type Source string

// Source values.
const (
	SourceUnknown Source = ""
	// SourceTSMPRecv is a TSMP reject message received from a peer.
	SourceTSMPRecv Source = "tsmp_recv"
	// SourceTSMPSent is a TSMP reject message this node emitted to a peer.
	SourceTSMPSent Source = "tsmp_sent"
	// SourcePendOpenTimeout is a pendopen-timer expiry with no response.
	SourcePendOpenTimeout Source = "pendopen_timeout"
)

// Reason is a short, stable, machine-readable tag describing why a
// connection was rejected. Reason is part of the aggregation key in
// [Aggregator].
//
// These values are part of the wire format exposed over the debug
// endpoints; do not rename or repurpose them without bumping the
// capability version.
type Reason string

// Reason values.
const (
	ReasonUnknown          Reason = "unknown"
	ReasonACL              Reason = "acl"
	ReasonShields          Reason = "shields"
	ReasonHostIPForwarding Reason = "host-ip-forwarding"
	ReasonHostFirewall     Reason = "host-firewall"
	ReasonNoPeer           Reason = "no-peer"
	ReasonPeerUnreachable  Reason = "peer-unreachable"
	ReasonTimeout          Reason = "timeout"
)

// Event is a single aggregated rejection observation.
//
// Events are aggregated by [Aggregator] on
// (Direction, Proto, peer-address, Reason). Src and Dst carry the ports
// observed on the most recent occurrence but do not participate in the
// aggregation key.
type Event struct {
	// First is when this (key) was first observed. If unset on a Note,
	// the aggregator fills it with the current time.
	First time.Time
	// Last is the most recent observation of this (key). If unset on a
	// Note, the aggregator fills it with the current time.
	Last time.Time
	// Count is the number of observations merged into this Event. If
	// unset on a Note, the aggregator treats it as 1.
	Count uint32
	// Direction indicates whether the event applies to an outgoing or
	// incoming connection attempt.
	Direction Direction
	// Proto is the transport protocol of the rejected flow.
	Proto ipproto.Proto
	// Src is a representative source endpoint from the most recent
	// observation. For Outgoing events this is our side; for Incoming
	// events this is the peer side.
	Src netip.AddrPort
	// Dst is a representative destination endpoint from the most recent
	// observation. For Outgoing events this is the peer side; for
	// Incoming events this is our side.
	Dst netip.AddrPort
	// Reason is the machine-readable reason tag.
	Reason Reason
	// Source describes how we learned about this event.
	Source Source
	// MaybeBroken is true for the non-terminal form of an inbound TSMP
	// reject (see packet.TailscaleRejectedHeader.MaybeBroken). It is
	// informational and only meaningful when Source == SourceTSMPRecv.
	MaybeBroken bool
}

// peerAddr returns the peer-side address for aggregation keying, based on
// the event's direction. For Outgoing, the peer is Dst; for Incoming, Src.
func (e Event) peerAddr() netip.Addr {
	switch e.Direction {
	case Outgoing:
		return e.Dst.Addr()
	case Incoming:
		return e.Src.Addr()
	}
	return netip.Addr{}
}

// aggKey is the aggregation key for an entry in an [Aggregator].
type aggKey struct {
	dir    Direction
	proto  ipproto.Proto
	addr   netip.Addr
	reason Reason
}

// entry is an internal aggregator entry.
type entry struct {
	k aggKey
	e Event
}

// dirBuf is an internal LRU+map for a single direction.
type dirBuf struct {
	m     map[aggKey]*list.Element // elements hold *entry
	order *list.List               // oldest (LRU) at Front, newest at Back
}

func newDirBuf() dirBuf {
	return dirBuf{
		m:     make(map[aggKey]*list.Element),
		order: list.New(),
	}
}

// Aggregator owns bounded, per-direction LRU buffers for rejection
// [Event]s and a runtime enable flag. It is safe for concurrent use.
//
// An Aggregator is per-[LocalBackend] (or per-test); there is no
// package-level state.
type Aggregator struct {
	max int // per-direction LRU capacity; <= 0 disables recording.

	enabled atomic.Bool

	mu       sync.Mutex
	outgoing dirBuf
	incoming dirBuf
}

// NewAggregator returns an [Aggregator] with per-direction LRU buffers
// sized to max entries each. It starts disabled (calls to Note are
// silently dropped until SetEnabled(true) is called).
//
// A max of 0 or negative disables recording entirely.
func NewAggregator(max int) *Aggregator {
	return &Aggregator{
		max:      max,
		outgoing: newDirBuf(),
		incoming: newDirBuf(),
	}
}

// SetEnabled sets the runtime enable flag. When false, Note is a silent
// no-op. SetEnabled returns the previous value.
func (a *Aggregator) SetEnabled(v bool) (prev bool) {
	return a.enabled.Swap(v)
}

// Enabled reports whether the aggregator is currently enabled.
func (a *Aggregator) Enabled() bool { return a.enabled.Load() }

// Note records a rejection observation. It is a no-op if the aggregator
// is disabled, if max is non-positive, or if e.Direction is not a
// routable value (Outgoing or Incoming).
//
// If an existing entry matches the aggregation key
// (Direction, Proto, peer-address, Reason), its Last, Count, Src, Dst,
// Source, and MaybeBroken are updated with the new observation, and it
// is moved to the "most recent" end of its buffer. Otherwise a new entry
// is appended, evicting the oldest entry if the buffer is over capacity.
func (a *Aggregator) Note(e Event) {
	if !a.enabled.Load() || a.max <= 0 {
		return
	}
	buf := a.bufFor(e.Direction)
	if buf == nil {
		return
	}
	if e.Last.IsZero() {
		e.Last = time.Now()
	}
	if e.First.IsZero() {
		e.First = e.Last
	}
	if e.Count == 0 {
		e.Count = 1
	}
	k := aggKey{
		dir:    e.Direction,
		proto:  e.Proto,
		addr:   e.peerAddr(),
		reason: e.Reason,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if el, ok := buf.m[k]; ok {
		ent := el.Value.(*entry)
		ent.e.Last = e.Last
		ent.e.Count += e.Count
		ent.e.Src = e.Src
		ent.e.Dst = e.Dst
		ent.e.Source = e.Source
		ent.e.MaybeBroken = e.MaybeBroken
		buf.order.MoveToBack(el)
		return
	}

	buf.m[k] = buf.order.PushBack(&entry{k: k, e: e})

	// Evict oldest if over capacity.
	for buf.order.Len() > a.max {
		old := buf.order.Front()
		delete(buf.m, old.Value.(*entry).k)
		buf.order.Remove(old)
	}
}

// Outgoing returns a snapshot of the outgoing-rejection events in
// oldest-to-newest order.
func (a *Aggregator) Outgoing() []Event { return a.snapshot(&a.outgoing) }

// Incoming returns a snapshot of the incoming-rejection events in
// oldest-to-newest order.
func (a *Aggregator) Incoming() []Event { return a.snapshot(&a.incoming) }

func (a *Aggregator) snapshot(buf *dirBuf) []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Event, 0, buf.order.Len())
	for el := buf.order.Front(); el != nil; el = el.Next() {
		out = append(out, el.Value.(*entry).e)
	}
	return out
}

// bufFor returns the internal buffer for a direction, or nil if the
// direction is not a recognized routable value.
//
// The returned pointer is stable for the lifetime of a; safe to use
// before acquiring a.mu.
func (a *Aggregator) bufFor(d Direction) *dirBuf {
	switch d {
	case Outgoing:
		return &a.outgoing
	case Incoming:
		return &a.incoming
	}
	return nil
}

// DefaultMax returns the default maximum number of entries per
// direction. On mobile platforms the default is smaller to respect tight
// memory budgets.
func DefaultMax() int {
	switch runtime.GOOS {
	case "ios", "android", "tvos":
		return 32
	}
	return 256
}

// DebugRejectsResponse is the JSON response body shared by the
// debug-rejects LocalAPI endpoint, the GET /debug/rejects c2n endpoint,
// and the [client/local.Client.DebugRejects] method.
type DebugRejectsResponse struct {
	// Enabled is whether [tailcfg.NodeAttrConnReject] is currently set
	// on the node. When false, Outgoing and Incoming will be empty
	// regardless of prior activity.
	Enabled bool
	// Outgoing is the list of rejections observed for connections this
	// node initiated.
	Outgoing []Event
	// Incoming is the list of rejections this node has emitted for
	// connections initiated by peers.
	Incoming []Event
}
