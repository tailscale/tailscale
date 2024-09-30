package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/util/mak"
)

type ipPool struct {
	perPeerMap syncs.Map[tailcfg.NodeID, *perPeerState]
	v4Ranges   []netip.Prefix
	dnsAddr    netip.Addr
	consensus  *consensus
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
func (cd *fsm) executeMarkLastUsed(bs []byte) commandResult {
	var args markLastUsedArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return commandResult{Err: err}
	}
	err = cd.applyMarkLastUsed(args.NodeID, args.Addr, args.Domain, args.UpdatedAt)
	if err != nil {
		return commandResult{Err: err}
	}
	return commandResult{}
}

func (ipp *fsm) applyMarkLastUsed(from tailcfg.NodeID, addr netip.Addr, domain string, updatedAt time.Time) error {
	// TODO lock
	ps, ok := ipp.perPeerMap.Load(from)
	if !ok {
		// unexpected in normal operation (but not an error?)
		return nil
	}
	ww, ok := ps.AddrToDomain.Lookup(addr)
	if !ok {
		// unexpected in normal operation (but not an error?)
		return nil
	}
	if ww.Domain != domain {
		// then I guess we're too late to update lastUsed
		return nil
	}
	if ww.LastUsed.After(updatedAt) {
		// prefer the most recent
		return nil
	}
	ww.LastUsed = updatedAt
	ps.AddrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), ww)
	return nil
}

func (ipp *ipPool) StartConsensus(peers []*ipnstate.PeerStatus, ts *tsnet.Server) {
	v4, _ := ts.TailscaleIPs()
	adminLn, err := ts.Listen("tcp", fmt.Sprintf("%s:6312", v4))
	if err != nil {
		log.Fatal(err)
	}
	raftLn, err := ts.Listen("tcp", fmt.Sprintf("%s:6311", v4))
	if err != nil {
		log.Fatal(err)
	}
	sl := StreamLayer{s: ts, Listener: raftLn}
	lns := listeners{command: adminLn, raft: &sl}
	cns, err := BootstrapConsensus((*fsm)(ipp), v4, &lns, peers, ts.HTTPClient())
	if err != nil {
		log.Fatalf("BootstrapConsensus failed: %v", err)
	}
	ipp.consensus = cns
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
	c := command{
		Name: "checkoutAddr",
		Args: bs,
	}
	result, err := cd.consensus.executeCommand(c)
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
	c := command{
		Name: "markLastUsed",
		Args: bs,
	}
	result, err := cd.consensus.executeCommand(c)
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
func (cd *fsm) executeCheckoutAddr(bs []byte) commandResult {
	var args checkoutAddrArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return commandResult{Err: err}
	}
	addr, err := cd.applyCheckoutAddr(args.NodeID, args.Domain, args.ReuseDeadline, args.UpdatedAt)
	if err != nil {
		return commandResult{Err: err}
	}
	resultBs, err := json.Marshal(addr)
	if err != nil {
		return commandResult{Err: err}
	}
	return commandResult{Result: resultBs}
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
