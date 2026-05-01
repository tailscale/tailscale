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

func (a *addrAssignments) insert(as *addrs) error {
	return a.insertWithExpiry(as, defaultExpiry)
}

func (a *addrAssignments) insertWithExpiry(as *addrs, d time.Duration) error {
	now := a.clock.Now()
	if !as.expiresAt.IsZero() && !as.expiresAt.Before(now) {
		return errors.New("expiresAt already set")
	}
	// we don't expect for addresses to be reused before expiry
	if existing, ok := a.byMagicIP[as.magic]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byMagicIP key exists")
		}
	}
	ddst := domainDst{domain: as.domain, dst: as.dst}
	if existing, ok := a.byDomainDst[ddst]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byDomainDst key exists")
		}
	}
	if existing, ok := a.byTransitIP[as.transit]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byTransitIP key exists")
		}
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
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return &addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (*addrs, bool) {
	v, ok := a.byMagicIP[mip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return &addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (*addrs, bool) {
	v, ok := a.byTransitIP[tip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return &addrs{}, false
	}
	return v, true
}

// popExpired returns the member of addrAssignments that expired earliest,
// or an invalid addrs if there are no expired members of addrAssignments.
func (a *addrAssignments) popExpired(now time.Time) *addrs {
	if a.byExpiresAt.Len() == 0 {
		return &addrs{}
	}
	if !a.byExpiresAt.peek().expiresAt.Before(now) {
		return &addrs{}
	}
	v := heap.Pop(&a.byExpiresAt).(*addrs)
	delete(a.byMagicIP, v.magic)
	delete(a.byTransitIP, v.transit)
	dd := domainDst{domain: v.domain, dst: v.dst}
	delete(a.byDomainDst, dd)
	return v
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
