// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ippool

// stuff that happens inside the consensus state machine

import (
	"errors"
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

// back and forth across the wire, and to disk
type consensusData struct {
	V4Ranges   []netip.Prefix
	PerPeerMap syncs.Map[tailcfg.NodeID, *perPeerState]
}

type perPeerState struct {
	DomainToAddr map[string]netip.Addr
	AddrToDomain *bart.Table[string]
}

func (ps *perPeerState) unusedIPV4(ranges []netip.Prefix) (netip.Addr, error) {
	// TODO here we iterate through each ip within the ranges until we find one that's unused
	// could be done more efficiently either by:
	//   1) storing an index into ranges and an ip we had last used from that range in perPeerState
	//			(how would this work with checking ips back into the pool though?)
	//   2) using a random approach like the natc does now, except the raft state machine needs to
	//      be deterministic so it can replay logs, so I think we would do something like generate a
	//      random ip each time, and then have a call into the state machine that says "give me whatever
	//      ip you have, and if you don't have one use this one". I think that would work.
	for _, r := range ranges {
		ip := r.Addr()
		for r.Contains(ip) {
			_, ok := ps.AddrToDomain.Lookup(ip)
			if !ok {
				return ip, nil
			}
			ip = ip.Next()
		}
	}
	return netip.Addr{}, errors.New("ip pool exhausted")
}

func (cd *consensusData) checkoutAddrForNode(nid tailcfg.NodeID, domain string) (netip.Addr, error) {
	pm, _ := cd.PerPeerMap.LoadOrStore(nid, &perPeerState{
		AddrToDomain: &bart.Table[string]{},
	})
	if existing, ok := pm.DomainToAddr[domain]; ok {
		return existing, nil
	}
	addr, err := pm.unusedIPV4(cd.V4Ranges)
	if err != nil {
		return netip.Addr{}, err
	}
	mak.Set(&pm.DomainToAddr, domain, addr)
	pm.AddrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), domain)
	//fmt.Println(nid, domain, addr, pm)
	return addr, nil
}

func (cd *consensusData) lookupDomain(nid tailcfg.NodeID, addr netip.Addr) string {
	// TODO what is the whole multiple value return story? would it be helpful to also be returning ok here?
	ps, ok := cd.PerPeerMap.Load(nid)
	if !ok {
		return ""
	}
	domain, ok := ps.AddrToDomain.Lookup(addr)
	if !ok {
		return ""
	}
	return domain
}
