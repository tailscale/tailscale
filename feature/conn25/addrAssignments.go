// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
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
// byConnKey stores netip.Prefix versions of the transit IPs for use in the
// WireGuard hooks.
type addrAssignments struct {
	byMagicIP   map[netip.Addr]addrs
	byTransitIP map[netip.Addr]addrs
	byDomainDst map[domainDst]addrs
	clock       tstime.Clock
}

const defaultExpiry = 48 * time.Hour

func (a *addrAssignments) insert(as addrs) error {
	return a.insertWithExpiry(as, defaultExpiry)
}

func (a *addrAssignments) insertWithExpiry(as addrs, d time.Duration) error {
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

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (addrs, bool) {
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (addrs, bool) {
	v, ok := a.byMagicIP[mip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (addrs, bool) {
	v, ok := a.byTransitIP[tip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}
