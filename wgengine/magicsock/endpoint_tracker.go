// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/heap"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	// endpointTrackerLifetime is how long we continue advertising an
	// endpoint after we last see it. This is intentionally chosen to be
	// slightly longer than a full netcheck period.
	endpointTrackerLifetime = 5*time.Minute + 10*time.Second

	// endpointTrackerMaxPerAddr is how many cached addresses we track for
	// a given netip.Addr. This allows e.g. restricting the number of STUN
	// endpoints we cache (which usually have the same netip.Addr but
	// different ports).
	//
	// The value of 6 is chosen because we can advertise up to 3 endpoints
	// based on the STUN IP:
	//    1. The STUN endpoint itself (EndpointSTUN)
	//    2. The STUN IP with the local Tailscale port (EndpointSTUN4LocalPort)
	//    3. The STUN IP with a portmapped port (EndpointPortmapped)
	//
	// Storing 6 endpoints in the cache means we can store up to 2 previous
	// sets of endpoints.
	endpointTrackerMaxPerAddr = 6
)

// endpointTrackerEntry is an entry in an endpointHeap that stores the state of
// a given cached endpoint.
type endpointTrackerEntry struct {
	// endpoint is the cached endpoint.
	endpoint tailcfg.Endpoint
	// until is the time until which this endpoint is being cached.
	until time.Time
	// index is the index within the containing endpointHeap.
	index int
}

// endpointHeap is an ordered heap of endpointTrackerEntry structs, ordered in
// ascending order by the 'until' expiry time (i.e. oldest first).
type endpointHeap []*endpointTrackerEntry

var _ heap.Interface[*endpointTrackerEntry] = (*endpointHeap)(nil)

// Len implements heap.Interface.
func (eh endpointHeap) Len() int { return len(eh) }

// Less implements heap.Interface.
func (eh endpointHeap) Less(i, j int) bool {
	// We want to store items so that the lowest item in the heap is the
	// oldest, so that heap.Pop()-ing from the endpointHeap will remove the
	// oldest entry.
	return eh[i].until.Before(eh[j].until)
}

// Swap implements heap.Interface.
func (eh endpointHeap) Swap(i, j int) {
	eh[i], eh[j] = eh[j], eh[i]
	eh[i].index = i
	eh[j].index = j
}

// Push implements heap.Interface.
func (eh *endpointHeap) Push(item *endpointTrackerEntry) {
	n := len(*eh)
	item.index = n
	*eh = append(*eh, item)
}

// Pop implements heap.Interface.
func (eh *endpointHeap) Pop() *endpointTrackerEntry {
	old := *eh
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*eh = old[0 : n-1]
	return item
}

// Min returns a pointer to the minimum element in the heap, without removing
// it. Since this is a min-heap ordered by the 'until' field, this returns the
// chronologically "earliest" element in the heap.
//
// Len() must be non-zero.
func (eh endpointHeap) Min() *endpointTrackerEntry {
	return eh[0]
}

// endpointTracker caches endpoints that are advertised to peers. This allows
// peers to still reach this node if there's a temporary endpoint flap; rather
// than withdrawing an endpoint and then re-advertising it the next time we run
// a netcheck, we keep advertising the endpoint until it's not present for a
// defined timeout.
//
// See tailscale/tailscale#7877 for more information.
type endpointTracker struct {
	mu        syncs.Mutex
	endpoints map[netip.Addr]*endpointHeap
}

// update takes as input the current sent of discovered endpoints and the
// current time, and returns the set of endpoints plus any previous-cached and
// non-expired endpoints that should be advertised to peers.
func (et *endpointTracker) update(now time.Time, eps []tailcfg.Endpoint) (epsPlusCached []tailcfg.Endpoint) {
	var inputEps set.Slice[netip.AddrPort]
	for _, ep := range eps {
		inputEps.Add(ep.Addr)
	}

	et.mu.Lock()
	defer et.mu.Unlock()

	// Extend endpoints that already exist in the cache. We do this before
	// we remove expired endpoints, below, so we don't remove something
	// that would otherwise have survived by extending.
	until := now.Add(endpointTrackerLifetime)
	for _, ep := range eps {
		et.extendLocked(ep, until)
	}

	// Now that we've extended existing endpoints, remove everything that
	// has expired.
	et.removeExpiredLocked(now)

	// Add entries from the input set of endpoints into the cache; we do
	// this after removing expired ones so that we can store as many as
	// possible, with space freed by the entries removed after expiry.
	for _, ep := range eps {
		et.addLocked(now, ep, until)
	}

	// Finally, add entries to the return array that aren't already there.
	epsPlusCached = eps
	for _, heap := range et.endpoints {
		for _, ep := range *heap {
			// If the endpoint was in the input list, or has expired, skip it.
			if inputEps.Contains(ep.endpoint.Addr) {
				continue
			} else if now.After(ep.until) {
				// Defense-in-depth; should never happen since
				// we removed expired entries above, but ignore
				// it anyway.
				continue
			}

			// We haven't seen this endpoint; add to the return array
			epsPlusCached = append(epsPlusCached, ep.endpoint)
		}
	}

	return epsPlusCached
}

// extendLocked will update the expiry time of the provided endpoint in the
// cache, if it is present. If it is not present, nothing will be done.
//
// et.mu must be held.
func (et *endpointTracker) extendLocked(ep tailcfg.Endpoint, until time.Time) {
	key := ep.Addr.Addr()
	epHeap, found := et.endpoints[key]
	if !found {
		return
	}

	// Find the entry for this exact address; this loop is quick since we
	// bound the number of items in the heap.
	//
	// TODO(andrew): this means we iterate over the entire heap once per
	// endpoint; even if the heap is small, if we have a lot of input
	// endpoints this can be expensive?
	for i, entry := range *epHeap {
		if entry.endpoint == ep {
			entry.until = until
			heap.Fix(epHeap, i)
			return
		}
	}
}

// addLocked will store the provided endpoint(s) in the cache for a fixed
// period of time, ensuring that the size of the endpoint cache remains below
// the maximum.
//
// et.mu must be held.
func (et *endpointTracker) addLocked(now time.Time, ep tailcfg.Endpoint, until time.Time) {
	key := ep.Addr.Addr()

	// Create or get the heap for this endpoint's addr
	epHeap := et.endpoints[key]
	if epHeap == nil {
		epHeap = new(endpointHeap)
		mak.Set(&et.endpoints, key, epHeap)
	}

	// Find the entry for this exact address; this loop is quick
	// since we bound the number of items in the heap.
	found := slices.ContainsFunc(*epHeap, func(v *endpointTrackerEntry) bool {
		return v.endpoint == ep
	})
	if !found {
		// Add address to heap; either the endpoint is new, or the heap
		// was newly-created and thus empty.
		heap.Push(epHeap, &endpointTrackerEntry{endpoint: ep, until: until})
	}

	// Now that we've added everything, pop from our heap until we're below
	// the limit. This is a min-heap, so popping removes the lowest (and
	// thus oldest) endpoint.
	for epHeap.Len() > endpointTrackerMaxPerAddr {
		heap.Pop(epHeap)
	}
}

// removeExpired will remove all expired entries from the cache.
//
// et.mu must be held.
func (et *endpointTracker) removeExpiredLocked(now time.Time) {
	for k, epHeap := range et.endpoints {
		// The minimum element is oldest/earliest endpoint; repeatedly
		// pop from the heap while it's in the past.
		for epHeap.Len() > 0 {
			minElem := epHeap.Min()
			if now.After(minElem.until) {
				heap.Pop(epHeap)
			} else {
				break
			}
		}

		if epHeap.Len() == 0 {
			// Free up space in the map by removing the empty heap.
			delete(et.endpoints, k)
		}
	}
}
