// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"sync/atomic"
	"time"
	"unique"

	"tailscale.com/types/key"
)

type flowKey struct {
	src, dst key.NodePublic
}

// flow tracks metadata about a directional flow of packets from a source
// node to a destination node. The public keys of the src is known
// by the caller.
type flow struct {
	createdUnixNano int64                  // int64 instead of time.Time to keep flow smaller
	index           int                    // index in Server.flows slice or -1 if not; guarded by Server.mu
	flowKey         unique.Handle[flowKey] // TODO: make this a unique handle of two unique handles for each NodePublic?

	roughActivityUnixTime atomic.Int64 // unix sec of recent activity, updated at most once a minute
	pktSendRegion         atomic.Int64
	byteSendRegion        atomic.Int64
	pktSendLocal          atomic.Int64
	byteSendLocal         atomic.Int64
	dropUnknownDest       atomic.Int64 // no local or region client for dest
	dropGone              atomic.Int64

	// ref is the reference count of things (*Server, *sclient) holding on
	// to this flow. As of 2024-09-18 it is currently only informational
	// and not used for anything. The Server adds/removes a ref count when
	// it's remove from its map and each 0, 1 or more sclients for a given
	// recently active flow also add/remove a ref count.
	//
	// This might be used in the future as an alternate Server.flow eviction
	// strategy but for now it's just a debug tool. We do want to keep flow
	// stats surviving a brief client disconnections, so we do want Server
	// to keep at least a momentary ref count alive.
	ref atomic.Int64
}

// noteActivity updates f.recentActivityUnixTime if it's been
// more than a minute.
func (f *flow) noteActivity() {
	now := time.Now().Unix()
	if now-f.roughActivityUnixTime.Load() > 60 {
		f.roughActivityUnixTime.Store(now)
	}
}

// getMakeFlow either gets or makes a new flow for the given source and
// destination nodes.
func (s *Server) getMakeFlow(src, dst key.NodePublic) *flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getMakeFlowLocked(src, dst)
}

func (s *Server) getMakeFlowLocked(src, dst key.NodePublic) *flow {
	k := flowKey{src, dst}
	f, ok := s.flow[k]
	if ok {
		return f
	}
	now := time.Now()
	f = &flow{
		createdUnixNano: now.UnixNano(),
		index:           len(s.flows),
		flowKey:         unique.Make(k),
	}
	f.roughActivityUnixTime.Store(now.Unix())
	f.ref.Add(1) // for Server's ref in the s.flows map itself

	// As penance for the one flow we're about to add to the map and slice
	// above, check two old flows for removal. We roll around and around the
	// flows slice, so this is a simple way to eventually check everything for
	// removal before we double in size.
	for range 2 {
		s.maybeCleanOldFlowLocked()
	}

	s.flow[k] = f
	s.flows = append(s.flows, f)

	return f
}

func (s *Server) maybeCleanOldFlowLocked() {
	if len(s.flows) == 0 {
		return
	}
	s.flowCleanIndex++
	if s.flowCleanIndex >= len(s.flows) {
		s.flowCleanIndex = 0
	}
	f := s.flows[s.flowCleanIndex]

	now := time.Now().Unix()
	ageSec := now - f.roughActivityUnixTime.Load()
	if ageSec > 3600 {
		// No activity in an hour. Remove it.
		delete(s.flow, f.flowKey.Value())
		holeIdx := f.index
		s.flows[holeIdx] = s.flows[len(s.flows)-1]
		s.flows[holeIdx].index = holeIdx
		s.flows = s.flows[:len(s.flows)-1]
		f.ref.Add(-1)
		return
	}
}

type flowAndClientSet struct {
	f  *flow      // always non-nil
	cs *clientSet // may be nil if peer not connected/known
}

// lookupDest returns the flow (always non-nil) and sclient and/or
// PacketForwarder (at least one of which will be nil, possibly both) for the
// given destination node.

// It must only be called from the [sclient.run] goroutine.
func (c *sclient) lookupDest(dst key.NodePublic) (_ *flow, _ *sclient, fwd PacketForwarder) {
	peer, ok := c.flows.GetOk(dst)
	if ok && peer.cs != nil {
		if c := peer.cs.activeClient.Load(); c != nil {
			// Common case for hot flows within the same node: we know the
			// clientSet and no mutex is needed.
			return peer.f, c, nil
		}
	}

	if peer.f == nil {
		peer.f = c.s.getMakeFlow(c.key, dst)
		peer.f.ref.Add(1)
		// At least store the flow in the map, even if we don't find the
		// clientSet later. In theory we could coallesce this map write with a
		// possible one later, but they should be rare and uncontended so we
		// don't care as of 2024-09-18.
		c.flows.Set(dst, peer)
		c.maybeCleanFlows()
	}

	srv := c.s
	srv.mu.Lock()
	set, ok := srv.clients[dst]
	if ok {
		if c := set.activeClient.Load(); c != nil {
			srv.mu.Unlock()
			peer.cs = set
			c.flows.Set(dst, peer)
			c.maybeCleanFlows()
			return peer.f, c, nil
		}
		fwd = srv.clientsMesh[dst]
	}
	srv.mu.Unlock()
	return peer.f, nil, fwd // fwd may be nil too
}

// maybeCleanFlows cleans the oldest element from the client flows cache if
// it's too big.
//
// It must only be called from the [sclient.run] goroutine.
func (c *sclient) maybeCleanFlows() {
	const maxClientFlowTrack = 100
	if c.flows.Len() <= maxClientFlowTrack {
		return
	}

	oldest, _ := c.flows.OldestKey()
	facs, ok := c.flows.PeekOk(oldest)
	if !ok {
		panic("lookupDest: OldestKey lied")
	}
	facs.f.ref.Add(-1)
	c.flows.Delete(oldest)
}
