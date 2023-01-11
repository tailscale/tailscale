// Copyright (c) 2023 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"time"

	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

// For extra defense-in-depth, when we're testing expired nodes we check
// ControlTime against this 'epoch' (set to the approximate time that this code
// was written) such that if control (or Headscale, etc.) sends a ControlTime
// that's sufficiently far in the past, we can safely ignore it.
var flagExpiredPeersEpoch = time.Unix(1673373066, 0)

// If the offset between the current time and the time received from control is
// larger than this, we store an offset in our expiryManager to adjust future
// clock timings.
const minClockDelta = 1 * time.Minute

// expiryManager tracks the state of expired nodes and the delta from the
// current clock time to the time returned from control, and allows mutating a
// netmap to mark peers as expired based on the current delta-adjusted time.
type expiryManager struct {
	// previouslyExpired stores nodes that have already expired so we can
	// only log on state transitions.
	previouslyExpired map[tailcfg.StableNodeID]bool

	// clockDelta stores the delta between the current time and the time
	// received from control such that:
	//    time.Now().Add(clockDelta) == MapResponse.ControlTime
	clockDelta syncs.AtomicValue[time.Duration]

	logf    logger.Logf
	timeNow func() time.Time
}

func newExpiryManager(logf logger.Logf) *expiryManager {
	return &expiryManager{
		previouslyExpired: map[tailcfg.StableNodeID]bool{},
		logf:              logf,
		timeNow:           time.Now,
	}
}

// onControlTime is called whenever we receive a new timestamp from the control
// server to store the delta.
func (em *expiryManager) onControlTime(t time.Time) {
	localNow := em.timeNow()
	delta := t.Sub(localNow)
	if delta.Abs() > minClockDelta {
		em.logf("[v1] netmap: flagExpiredPeers: setting clock delta to %v", delta)
		em.clockDelta.Store(delta)
	} else {
		em.clockDelta.Store(0)
	}
}

// flagExpiredPeers updates mapRes.Peers, mutating all peers that have expired,
// taking into account any clock skew detected by using the ControlTime field
// in the MapResponse. We don't actually remove expired peers from the Peers
// array; instead, we clear some fields of the Node object, and set
// Node.Expired so other parts of the codebase can provide more clear error
// messages when attempting to e.g. ping an expired node.
//
// This is additionally a defense-in-depth against something going wrong with
// control such that we start seeing expired peers with a valid Endpoints or
// DERP field.
//
// This function is safe to call concurrently with onControlTime but not
// concurrently with any other call to flagExpiredPeers.
func (em *expiryManager) flagExpiredPeers(netmap *netmap.NetworkMap) {
	localNow := em.timeNow()

	// Adjust our current time by any saved delta to adjust for clock skew.
	controlNow := localNow.Add(em.clockDelta.Load())
	if controlNow.Before(flagExpiredPeersEpoch) {
		em.logf("netmap: flagExpiredPeers: [unexpected] delta-adjusted current time is before hardcoded epoch; skipping")
		return
	}

	for _, peer := range netmap.Peers {
		// Nodes that don't expire have KeyExpiry set to the zero time;
		// skip those and peers that are already marked as expired
		// (e.g. from control).
		if peer.KeyExpiry.IsZero() || peer.KeyExpiry.After(controlNow) {
			delete(em.previouslyExpired, peer.StableID)
			continue
		} else if peer.Expired {
			continue
		}

		if !em.previouslyExpired[peer.StableID] {
			em.logf("[v1] netmap: flagExpiredPeers: clearing expired peer %v", peer.StableID)
			em.previouslyExpired[peer.StableID] = true
		}

		// Actually mark the node as expired
		peer.Expired = true

		// Control clears the Endpoints and DERP fields of expired
		// nodes; do so here as well. The Expired bool is the correct
		// thing to set, but this replicates the previous behaviour.
		//
		// NOTE: this is insufficient to actually break connectivity,
		// since we discover endpoints via DERP, and due to DERP return
		// path optimization.
		peer.Endpoints = nil
		peer.DERP = ""

		// Defense-in-depth: break the node's public key as well, in
		// case something tries to communicate.
		peer.Key = key.NodePublicWithBadOldPrefix(peer.Key)
	}
}
