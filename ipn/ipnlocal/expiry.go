// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"time"

	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
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

	logf  logger.Logf
	clock tstime.Clock
}

func newExpiryManager(logf logger.Logf) *expiryManager {
	return &expiryManager{
		previouslyExpired: map[tailcfg.StableNodeID]bool{},
		logf:              logf,
		clock:             tstime.StdClock{},
	}
}

// onControlTime is called whenever we receive a new timestamp from the control
// server to store the delta.
func (em *expiryManager) onControlTime(t time.Time) {
	localNow := em.clock.Now()
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
// The localNow time should be the output of time.Now for the local system; it
// will be adjusted by any stored clock skew from ControlTime.
//
// This is additionally a defense-in-depth against something going wrong with
// control such that we start seeing expired peers with a valid Endpoints or
// DERP field.
//
// This function is safe to call concurrently with onControlTime but not
// concurrently with any other call to flagExpiredPeers.
func (em *expiryManager) flagExpiredPeers(netmap *netmap.NetworkMap, localNow time.Time) {
	// Adjust our current time by any saved delta to adjust for clock skew.
	controlNow := localNow.Add(em.clockDelta.Load())
	if controlNow.Before(flagExpiredPeersEpoch) {
		em.logf("netmap: flagExpiredPeers: [unexpected] delta-adjusted current time is before hardcoded epoch; skipping")
		return
	}

	for i, peer := range netmap.Peers {
		// Nodes that don't expire have KeyExpiry set to the zero time;
		// skip those and peers that are already marked as expired
		// (e.g. from control).
		if peer.KeyExpiry().IsZero() || peer.KeyExpiry().After(controlNow) {
			delete(em.previouslyExpired, peer.StableID())
			continue
		} else if peer.Expired() {
			continue
		}

		if !em.previouslyExpired[peer.StableID()] {
			em.logf("[v1] netmap: flagExpiredPeers: clearing expired peer %v", peer.StableID())
			em.previouslyExpired[peer.StableID()] = true
		}

		mut := peer.AsStruct()

		// Actually mark the node as expired
		mut.Expired = true

		// Control clears the Endpoints and DERP fields of expired
		// nodes; do so here as well. The Expired bool is the correct
		// thing to set, but this replicates the previous behaviour.
		//
		// NOTE: this is insufficient to actually break connectivity,
		// since we discover endpoints via DERP, and due to DERP return
		// path optimization.
		mut.Endpoints = nil
		mut.DERP = ""

		// Defense-in-depth: break the node's public key as well, in
		// case something tries to communicate.
		mut.Key = key.NodePublicWithBadOldPrefix(peer.Key())

		netmap.Peers[i] = mut.View()
	}
}

// nextPeerExpiry returns the time that the next node in the netmap expires
// (including the self node), based on their KeyExpiry. It skips nodes that are
// already marked as Expired. If there are no nodes expiring in the future,
// then the zero Time will be returned.
//
// The localNow time should be the output of time.Now for the local system; it
// will be adjusted by any stored clock skew from ControlTime.
//
// This function is safe to call concurrently with other methods of this expiryManager.
func (em *expiryManager) nextPeerExpiry(nm *netmap.NetworkMap, localNow time.Time) time.Time {
	if nm == nil {
		return time.Time{}
	}

	controlNow := localNow.Add(em.clockDelta.Load())
	if controlNow.Before(flagExpiredPeersEpoch) {
		em.logf("netmap: nextPeerExpiry: [unexpected] delta-adjusted current time is before hardcoded epoch; skipping")
		return time.Time{}
	}

	var nextExpiry time.Time // zero if none
	for _, peer := range nm.Peers {
		if peer.KeyExpiry().IsZero() {
			continue // tagged node
		} else if peer.Expired() {
			// Peer already expired; Expired is set by the
			// flagExpiredPeers function, above.
			continue
		} else if peer.KeyExpiry().Before(controlNow) {
			// This peer already expired, and peer.Expired
			// isn't set for some reason. Skip this node.
			continue
		}

		// nextExpiry being zero is a sentinel that we haven't yet set
		// an expiry; otherwise, only update if this node's expiry is
		// sooner than the currently-stored one (since we want the
		// soonest-occurring expiry time).
		if nextExpiry.IsZero() || peer.KeyExpiry().Before(nextExpiry) {
			nextExpiry = peer.KeyExpiry()
		}
	}

	// Ensure that we also fire this timer if our own node key expires.
	if nm.SelfNode.Valid() {
		selfExpiry := nm.SelfNode.KeyExpiry()

		if selfExpiry.IsZero() {
			// No expiry for self node
		} else if selfExpiry.Before(controlNow) {
			// Self node already expired; we don't want to return a
			// time in the past, so skip this.
		} else if nextExpiry.IsZero() || selfExpiry.Before(nextExpiry) {
			// Self node expires after now, but before the soonest
			// peer in the netmap; update our next expiry to this
			// time.
			nextExpiry = selfExpiry
		}
	}

	// As an additional defense in depth, never return a time that is
	// before the current time from the perspective of the local system
	// (since timers with a zero or negative duration will fire
	// immediately and can cause unnecessary reconfigurations).
	//
	// This can happen if the local clock is running fast; for example:
	//    localTime   = 2pm
	//    controlTime = 1pm    (real time)
	//    nextExpiry  = 1:30pm (real time)
	//
	// In the above case, we'd return a nextExpiry of 1:30pm while the
	// current clock reads 2pm; in this case, setting a timer for
	// nextExpiry.Sub(now) would result in a negative duration and a timer
	// that fired immediately.
	//
	// In this particular edge-case, return an expiry time 30 seconds after
	// the local time so that any timers created based on this expiry won't
	// fire too quickly.
	//
	// The alternative would be to do all comparisons in local time,
	// unadjusted for clock skew, but that doesn't handle cases where the
	// local clock is "fixed" between netmap updates.
	if !nextExpiry.IsZero() && nextExpiry.Before(localNow) {
		em.logf("netmap: nextPeerExpiry: skipping nextExpiry %q before local time %q due to clock skew",
			nextExpiry.UTC().Format(time.RFC3339),
			localNow.UTC().Format(time.RFC3339))
		return localNow.Add(30 * time.Second)
	}

	return nextExpiry
}

// ControlNow estimates the current time on the control server, calculated as
// localNow + the delta between local and control server clocks as recorded
// when the LocalBackend last received a time message from the control server.
func (b *LocalBackend) ControlNow(localNow time.Time) time.Time {
	return localNow.Add(b.em.clockDelta.Load())
}
