package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsconsensus"
	"tailscale.com/tsnet"
	"tailscale.com/util/mak"
)

/*
An ipPool is a group of one or more IPV4 ranges from which individual IPV4 addresses can be
checked out.

natc-consensus provides per domain router functionality for a tailnet.
  - when a node does a dns lookup for a domain the natc-consensus handles, natc-consensus asks ipPool for an IP address
    for that node and domain. When ipPool
  - when a node sends traffic to the IP address it has for a domain, natc-consensus asks ipPool which domain that traffic
    is for.
  - when an IP address hasn't been used for a while ipPool forgets about that node-ip-domain mapping and may provide
    that IP address to that node in response to a subsequent DNS request.

The pool is distributed across servers in a cluster, to provide high availability.

Each tailcfg.NodeID has the full range available. The same IPV4 address will be provided to different nodes.

ipPool will maintain the node-ip-domain mapping until it expires, and won't hand out the IP address to that node
again while it maintains the mapping.

Reading from the pool is fast, writing to the pool is slow. Because reads can be done in memory on the server that got
the traffic, but writes must be sent to the consensus peers.

To handle expiry we write on reads, to update the last-used-date, but we do that after we've returned a response.

ipPool.DomainForIP gets the domain associated with a previous IP checkout for a node

ipPool.IPForDomain gets an IP address for the node+domain. It will return an IP address from any existing mapping,
or it may create a mapping with a new unused IP address.
*/
type ipPool struct {
	perPeerMap syncs.Map[tailcfg.NodeID, *perPeerState]
	v4Ranges   []netip.Prefix
	dnsAddr    netip.Addr
	consensus  *tsconsensus.Consensus
}

func (ipp *ipPool) DomainForIP(from tailcfg.NodeID, addr netip.Addr, updatedAt time.Time) string {
	// TODO lock
	pm, ok := ipp.perPeerMap.Load(from)
	if !ok {
		log.Printf("DomainForIP: peer state absent for: %d", from)
		return ""
	}
	ww, ok := pm.AddrToDomain.Lookup(addr)
	if !ok {
		log.Printf("DomainForIP: peer state doesn't recognize domain")
		return ""
	}
	go func() {
		err := ipp.markLastUsed(from, addr, ww.Domain, updatedAt)
		if err != nil {
			panic(err)
		}
	}()
	return ww.Domain
}

type markLastUsedArgs struct {
	NodeID    tailcfg.NodeID
	Addr      netip.Addr
	Domain    string
	UpdatedAt time.Time
}

// called by raft
func (cd *fsm) executeMarkLastUsed(bs []byte) tsconsensus.CommandResult {
	var args markLastUsedArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	err = cd.applyMarkLastUsed(args.NodeID, args.Addr, args.Domain, args.UpdatedAt)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	return tsconsensus.CommandResult{}
}

func (ipp *fsm) applyMarkLastUsed(from tailcfg.NodeID, addr netip.Addr, domain string, updatedAt time.Time) error {
	// TODO lock
	ps, ok := ipp.perPeerMap.Load(from)
	if !ok {
		// There's nothing to mark. But this is unexpected, because we mark last used after we do things with peer state.
		log.Printf("applyMarkLastUsed: could not find peer state, nodeID: %s", from)
		return nil
	}
	ww, ok := ps.AddrToDomain.Lookup(addr)
	if !ok {
		// The peer state didn't have an entry for the IP address (possibly it expired), so there's nothing to mark.
		return nil
	}
	if ww.Domain != domain {
		// The IP address expired and was reused for a new domain. Don't mark.
		return nil
	}
	if ww.LastUsed.After(updatedAt) {
		// This has been marked more recently. Don't mark.
		return nil
	}
	ww.LastUsed = updatedAt
	ps.AddrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), ww)
	return nil
}

func (ipp *ipPool) StartConsensus(ctx context.Context, ts *tsnet.Server, clusterTag string) error {
	cns, err := tsconsensus.Start(ctx, ts, (*fsm)(ipp), clusterTag, tsconsensus.DefaultConfig())
	if err != nil {
		return err
	}
	ipp.consensus = cns
	return nil
}

type whereWhen struct {
	Domain   string
	LastUsed time.Time
}

type perPeerState struct {
	DomainToAddr map[string]netip.Addr
	AddrToDomain *bart.Table[whereWhen]
	mu           sync.Mutex // not jsonified
}

func (ps *perPeerState) unusedIPV4(ranges []netip.Prefix, exclude netip.Addr, reuseDeadline time.Time) (netip.Addr, bool, string, error) {
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
			if ip != exclude {
				ww, ok := ps.AddrToDomain.Lookup(ip)
				if !ok {
					return ip, false, "", nil
				}
				if ww.LastUsed.Before(reuseDeadline) {
					return ip, true, ww.Domain, nil
				}
			}
			ip = ip.Next()
		}
	}
	return netip.Addr{}, false, "", errors.New("ip pool exhausted")
}

func (cd *ipPool) IpForDomain(nid tailcfg.NodeID, domain string) (netip.Addr, error) {
	now := time.Now()
	args := checkoutAddrArgs{
		NodeID:        nid,
		Domain:        domain,
		ReuseDeadline: now.Add(-10 * time.Second), // TODO what time period? 48 hours?
		UpdatedAt:     now,
	}
	bs, err := json.Marshal(args)
	if err != nil {
		return netip.Addr{}, err
	}
	c := tsconsensus.Command{
		Name: "checkoutAddr",
		Args: bs,
	}
	result, err := cd.consensus.ExecuteCommand(c)
	if err != nil {
		log.Printf("IpForDomain: raft error executing command: %v", err)
		return netip.Addr{}, err
	}
	if result.Err != nil {
		log.Printf("IpForDomain: error returned from state machine: %v", err)
		return netip.Addr{}, result.Err
	}
	var addr netip.Addr
	err = json.Unmarshal(result.Result, &addr)
	return addr, err
}

func (cd *ipPool) markLastUsed(nid tailcfg.NodeID, addr netip.Addr, domain string, lastUsed time.Time) error {
	args := markLastUsedArgs{
		NodeID:    nid,
		Addr:      addr,
		Domain:    domain,
		UpdatedAt: lastUsed,
	}
	bs, err := json.Marshal(args)
	if err != nil {
		return err
	}
	//c := command{
	c := tsconsensus.Command{
		Name: "markLastUsed",
		Args: bs,
	}
	result, err := cd.consensus.ExecuteCommand(c)
	if err != nil {
		log.Printf("markLastUsed: raft error executing command: %v", err)
		return err
	}
	if result.Err != nil {
		log.Printf("markLastUsed: error returned from state machine: %v", err)
		return result.Err
	}
	return nil
}

type checkoutAddrArgs struct {
	NodeID        tailcfg.NodeID
	Domain        string
	ReuseDeadline time.Time
	UpdatedAt     time.Time
}

// called by raft
func (cd *fsm) executeCheckoutAddr(bs []byte) tsconsensus.CommandResult {
	var args checkoutAddrArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	addr, err := cd.applyCheckoutAddr(args.NodeID, args.Domain, args.ReuseDeadline, args.UpdatedAt)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	resultBs, err := json.Marshal(addr)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	return tsconsensus.CommandResult{Result: resultBs}
}

func (cd *fsm) applyCheckoutAddr(nid tailcfg.NodeID, domain string, reuseDeadline, updatedAt time.Time) (netip.Addr, error) {
	// TODO lock and unlock
	pm, _ := cd.perPeerMap.LoadOrStore(nid, &perPeerState{
		AddrToDomain: &bart.Table[whereWhen]{},
	})
	if existing, ok := pm.DomainToAddr[domain]; ok {
		// TODO handle error case where this doesn't exist
		ww, _ := pm.AddrToDomain.Lookup(existing)
		ww.LastUsed = updatedAt
		pm.AddrToDomain.Insert(netip.PrefixFrom(existing, existing.BitLen()), ww)
		return existing, nil
	}
	addr, wasInUse, previousDomain, err := pm.unusedIPV4(cd.v4Ranges, cd.dnsAddr, reuseDeadline)
	if err != nil {
		return netip.Addr{}, err
	}
	mak.Set(&pm.DomainToAddr, domain, addr)
	if wasInUse {
		// remove it from domaintoaddr
		delete(pm.DomainToAddr, previousDomain)
		// don't need to remove it from addrtodomain, insert will do that
	}
	pm.AddrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), whereWhen{Domain: domain, LastUsed: updatedAt})
	return addr, nil
}
