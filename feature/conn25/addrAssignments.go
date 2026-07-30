// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"container/heap"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
)

// domainDst is a key for looking up an existing address assignment by the
// DNS response domain and destination IP pair.
type domainDst struct {
	domain dnsname.FQDN
	dst    netip.Addr
}

// addrAssignments is the collection of addrs assigned by this client
// supporting lookup by magic IP, transit IP or domain+dst, or to lookup all
// transit IPs associated with a given connector (identified by its node key).
type addrAssignments struct {
	byMagicIP   map[netip.Addr]*addrs
	byTransitIP map[netip.Addr]*addrs
	byDomainDst map[domainDst]*addrs
	byExpiresAt addrsHeap
	clock       tstime.Clock
}

const defaultExpiry = 48 * time.Hour

func clampExpiryFromTTL(ttl time.Duration) time.Duration {
	const minTTL = time.Minute * 1
	const maxTTL = time.Hour * 72
	expiry := max(minTTL, ttl)
	return min(maxTTL, expiry)
}

func (a *addrAssignments) insert(as *addrs) error {
	return a.insertWithExpiry(as, defaultExpiry)
}

func (a *addrAssignments) insertFromTTL(as *addrs, ttl time.Duration) error {
	return a.insertWithExpiry(as, clampExpiryFromTTL(ttl))
}

func (a *addrAssignments) updateFromTTL(as *addrs, ttl time.Duration) {
	a.updateExpiry(as, clampExpiryFromTTL(ttl))
}

func (a *addrAssignments) insertWithExpiry(as *addrs, d time.Duration) error {
	now := a.clock.Now()
	if !as.expiresAt.IsZero() && !as.expiresAt.Before(now) {
		return errors.New("expiresAt already set")
	}
	// addresses must be removed (eg by popExpired) before they can be reused
	if _, ok := a.byMagicIP[as.magic]; ok {
		return errors.New("byMagicIP key exists")
	}
	ddst := domainDst{domain: as.domain, dst: as.dst}
	if _, ok := a.byDomainDst[ddst]; ok {
		return errors.New("byDomainDst key exists")
	}
	if _, ok := a.byTransitIP[as.transit]; ok {
		return errors.New("byTransitIP key exists")
	}
	as.expiresAt = now.Add(d)
	mak.Set(&a.byMagicIP, as.magic, as)
	mak.Set(&a.byTransitIP, as.transit, as)
	mak.Set(&a.byDomainDst, ddst, as)
	heap.Push(&a.byExpiresAt, as)
	return nil
}

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (*addrs, bool) {
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	if !ok {
		return &addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (*addrs, bool) {
	v, ok := a.byMagicIP[mip]
	if !ok {
		return &addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (*addrs, bool) {
	v, ok := a.byTransitIP[tip]
	if !ok {
		return &addrs{}, false
	}
	return v, true
}

const (
	// deadFlowWaitTimeout is the minimum time after the active flow count
	// drops to zero that we keep an address mapping in our table of address
	// mappings.
	deadFlowWaitTimeout = 2 * time.Minute

	// extendForActiveFlowDuration is the minimum time we will wait to recheck
	// an address mapping with a positive active flow count for removal from
	// the table of address mappings.
	extendForActiveFlowDuration = 24 * time.Hour
)

// popExpired attempts to remove from all the indexes one address
// mapping, and return that mapping, or nil if there were no eligible mappings.
// An address mapping is eligible for removal if:
// - the current time is past the expiresAt time on the mapping
// - and, the active flow count is 0
// - and, it's been long enough since the active flow count dropped to 0
// We're using a heap on expiresAt to efficiently find addresses that
// are eligible for removal. expiresAt is initially set according to the
// TTL on the DNS response. If the current time is past the expiresAt, but
// there are active flows, we extend the expiresAt time into the future.
func (a *addrAssignments) popExpired(now time.Time) *addrs {
	if a.byExpiresAt.Len() == 0 {
		return nil
	}
	var v *addrs
	// Look for an address we can remove.
	for {
		if !a.byExpiresAt.peek().expiresAt.Before(now) {
			// There's no longer anything outside the expiry window.
			return nil
		}
		candidate := heap.Pop(&a.byExpiresAt).(*addrs)
		if candidate.activeFlowCount == 0 && candidate.zeroFlowTime.Add(deadFlowWaitTimeout).Before(now) {
			// Found one.
			v = candidate
			break
		}
		// Candidate can't be removed due to active flows. Extend expiresAt, and put it back in the heap.
		candidate.expiresAt = now.Add(extendForActiveFlowDuration)
		// TODO(mzb/fran): This is an expensive operation we could consider optimizing.
		heap.Push(&a.byExpiresAt, candidate)
	}
	delete(a.byMagicIP, v.magic)
	delete(a.byTransitIP, v.transit)
	dd := domainDst{domain: v.domain, dst: v.dst}
	delete(a.byDomainDst, dd)
	return v
}

func (a *addrAssignments) updateExpiry(as *addrs, expiresIn time.Duration) {
	now := a.clock.Now()
	as.expiresAt = now.Add(expiresIn)
	// TODO(fran) 2026-05-26 We can make this perform better.
	//  * With a bit of extra effort, we can track the index so that heap.Fix can
	//    be used.
	//  * Alternatively, marking the heap dirty and waiting until the next
	//    operation that requires it to be in the correct order would mean a
	//    whole slew of updates can accumulate before paying for a heap.Init.
	heap.Init(&a.byExpiresAt)
}

type addrsHeap []*addrs

func (h addrsHeap) Len() int           { return len(h) }
func (h addrsHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h addrsHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *addrsHeap) Push(x any) {
	as, ok := x.(*addrs)
	if !ok {
		panic("unexpected not an addrs")
	}
	*h = append(*h, as)
}
func (h *addrsHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
func (h addrsHeap) peek() *addrs {
	return (h)[0]
}
