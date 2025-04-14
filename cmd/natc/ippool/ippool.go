// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// ippool implements IP address storage, creation, and retrieval for cmd/natc
package ippool

import (
	"errors"
	"log"
	"math/big"
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"go4.org/netipx"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
)

var ErrNoIPsAvailable = errors.New("no IPs available")

type IPPool struct {
	perPeerMap syncs.Map[tailcfg.NodeID, *perPeerState]
	IPSet      *netipx.IPSet
}

func (ipp *IPPool) DomainForIP(from tailcfg.NodeID, addr netip.Addr) (string, bool) {
	ps, ok := ipp.perPeerMap.Load(from)
	if !ok {
		log.Printf("handleTCPFlow: no perPeerState for %v", from)
		return "", false
	}
	domain, ok := ps.domainForIP(addr)
	if !ok {
		log.Printf("handleTCPFlow: no domain for IP %v\n", addr)
		return "", false
	}
	return domain, ok
}

func (ipp *IPPool) IPForDomain(from tailcfg.NodeID, domain string) (netip.Addr, error) {
	npps := &perPeerState{
		ipset: ipp.IPSet,
	}
	ps, _ := ipp.perPeerMap.LoadOrStore(from, npps)
	return ps.ipForDomain(domain)
}

// perPeerState holds the state for a single peer.
type perPeerState struct {
	ipset *netipx.IPSet

	mu           sync.Mutex
	addrInUse    *big.Int
	domainToAddr map[string]netip.Addr
	addrToDomain *bart.Table[string]
}

// domainForIP returns the domain name assigned to the given IP address and
// whether it was found.
func (ps *perPeerState) domainForIP(ip netip.Addr) (_ string, ok bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.addrToDomain == nil {
		return "", false
	}
	return ps.addrToDomain.Lookup(ip)
}

// ipForDomain assigns a pair of unique IP addresses for the given domain and
// returns them. The first address is an IPv4 address and the second is an IPv6
// address. If the domain already has assigned addresses, it returns them.
func (ps *perPeerState) ipForDomain(domain string) (netip.Addr, error) {
	fqdn, err := dnsname.ToFQDN(domain)
	if err != nil {
		return netip.Addr{}, err
	}
	domain = fqdn.WithoutTrailingDot()

	ps.mu.Lock()
	defer ps.mu.Unlock()
	if addr, ok := ps.domainToAddr[domain]; ok {
		return addr, nil
	}
	addr := ps.assignAddrsLocked(domain)
	if !addr.IsValid() {
		return netip.Addr{}, ErrNoIPsAvailable
	}
	return addr, nil
}

// unusedIPv4Locked returns an unused IPv4 address from the available ranges.
func (ps *perPeerState) unusedIPv4Locked() netip.Addr {
	if ps.addrInUse == nil {
		ps.addrInUse = big.NewInt(0)
	}
	return allocAddr(ps.ipset, ps.addrInUse)
}

// assignAddrsLocked assigns a pair of unique IP addresses for the given domain
// and returns them. The first address is an IPv4 address and the second is an
// IPv6 address. It does not check if the domain already has assigned addresses.
// ps.mu must be held.
func (ps *perPeerState) assignAddrsLocked(domain string) netip.Addr {
	if ps.addrToDomain == nil {
		ps.addrToDomain = &bart.Table[string]{}
	}
	v4 := ps.unusedIPv4Locked()
	if !v4.IsValid() {
		return netip.Addr{}
	}
	addr := v4
	mak.Set(&ps.domainToAddr, domain, addr)
	ps.addrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), domain)
	return addr
}
