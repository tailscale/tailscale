// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"context"
	"errors"
	"net/netip"
	"sync"
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
// byConnKey stores netip.Prefix versions of the transit IPs for use in the
// WireGuard hooks.
type addrAssignments struct {
	clock tstime.Clock

	mu          sync.Mutex // protects fields below
	byMagicIP   map[netip.Addr]addrs
	byTransitIP map[netip.Addr]addrs
	byDomainDst map[domainDst]addrs
}

const defaultExpiry = 48 * time.Hour

func (a *addrAssignments) insert(as addrs) error {
	return a.insertWithExpiry(as, defaultExpiry)
}

func (a *addrAssignments) insertWithExpiry(as addrs, d time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !as.expiresAt.IsZero() {
		return errors.New("expiresAt already set")
	}
	now := a.clock.Now()
	as.expiresAt = now.Add(d)
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
	mak.Set(&a.byMagicIP, as.magic, as)
	mak.Set(&a.byTransitIP, as.transit, as)
	mak.Set(&a.byDomainDst, ddst, as)
	return nil
}

func (a *addrAssignments) remove(as addrs) {
	delete(a.byMagicIP, as.magic)
	ddst := domainDst{domain: as.domain, dst: as.dst}
	delete(a.byDomainDst, ddst)
	delete(a.byTransitIP, as.transit)
}

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (addrs, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (addrs, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.byMagicIP[mip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (addrs, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.byTransitIP[tip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) removeExpiredAddrs() []addrs {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Now()
	var removed []addrs
	for _, ad := range a.byMagicIP {
		if ad.expiresAt.Before(now) {
			a.remove(ad)
			removed = append(removed, ad)
		}
	}
	return removed
}

func (a *addrAssignments) expireAddrAssignmentsLoop(ctx context.Context) {
	ticker, ch := a.clock.NewTicker(61 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			a.removeExpiredAddrs()
		}
	}
}
