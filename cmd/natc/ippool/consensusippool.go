// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	"github.com/hashicorp/raft"
	"go4.org/netipx"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsconsensus"
	"tailscale.com/tsnet"
	"tailscale.com/util/mak"
)

// A ConsensusIPPool is an IPSet from which individual IPV4 addresses can be checked out.
//
// The pool is distributed across servers in a cluster, to provide high availability.
//
// Each tailcfg.NodeID has the full range available. The same IPV4 address will be provided to different nodes.
//
// ConsensusIPPool will maintain the node-ip-domain mapping until it expires, and won't hand out the IP address to that node
// again while it maintains the mapping.
//
// Reading from the pool is fast, writing to the pool is slow. Because reads can be done in memory on the server that got
// the traffic, but writes must be sent to the consensus peers.
//
// To handle expiry we write on reads, to update the last-used-date, but we do that after we've returned a response.
type ConsensusIPPool struct {
	IPSet      *netipx.IPSet
	perPeerMap *syncs.Map[tailcfg.NodeID, *consensusPerPeerState]
	consensus  commandExecutor
}

func NewConsensusIPPool(ipSet *netipx.IPSet) *ConsensusIPPool {
	return &ConsensusIPPool{
		IPSet:      ipSet,
		perPeerMap: &syncs.Map[tailcfg.NodeID, *consensusPerPeerState]{},
	}
}

// DomainForIP is part of the IPPool interface. It returns a domain for a given IP address, if we have
// previously assigned the IP address to a domain for the node that is asking. Otherwise it logs and returns the empty string.
func (ipp *ConsensusIPPool) DomainForIP(from tailcfg.NodeID, addr netip.Addr, updatedAt time.Time) (string, bool) {
	ww, ok := ipp.retryDomainLookup(from, addr, 0)
	if !ok {
		return "", false
	}
	go func() {
		err := ipp.markLastUsed(from, addr, ww.Domain, updatedAt)
		if err != nil {
			panic(err)
		}
	}()
	return ww.Domain, true
}

// retryDomainLookup tries to lookup the domain for this IP+node. If it can't find the node or the IP it
// tries again up to 5 times, with exponential backoff.
// The raft lib will tell the leader that a log entry has been applied to a quorum of nodes, sometimes before the
// log entry has been applied to the local state. This means that in our case the traffic on an IP can arrive before
// we have the domain for which that IP applies stored.
func (ipp *ConsensusIPPool) retryDomainLookup(from tailcfg.NodeID, addr netip.Addr, n int) (whereWhen, bool) {
	ps, foundPeerState := ipp.perPeerMap.Load(from)
	if foundPeerState {
		ps.mu.Lock()
		ww, foundDomain := ps.addrToDomain.Lookup(addr)
		ps.mu.Unlock()
		if foundDomain {
			return ww, true
		}
	}
	if n > 4 {
		if !foundPeerState {
			log.Printf("DomainForIP: peer state absent for: %d", from)
		} else {
			log.Printf("DomainForIP: peer state doesn't recognize addr: %s", addr)
		}
		return whereWhen{}, false
	}
	timeToWait := 100
	for i := 0; i < n; i++ {
		timeToWait *= 2
	}
	time.Sleep(time.Millisecond * time.Duration(timeToWait))
	return ipp.retryDomainLookup(from, addr, n+1)
}

// StartConsensus is part of the IPPool interface. It starts the raft background routines that handle consensus.
func (ipp *ConsensusIPPool) StartConsensus(ctx context.Context, ts *tsnet.Server, clusterTag string) error {
	cfg := tsconsensus.DefaultConfig()
	cfg.ServeDebugMonitor = true
	cns, err := tsconsensus.Start(ctx, ts, ipp, clusterTag, cfg)
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

type consensusPerPeerState struct {
	domainToAddr map[string]netip.Addr
	addrToDomain *bart.Table[whereWhen]
	mu           sync.Mutex
}

// StopConsensus is part of the IPPool interface. It stops the raft background routines that handle consensus.
func (ipp *ConsensusIPPool) StopConsensus(ctx context.Context) error {
	return (ipp.consensus).(*tsconsensus.Consensus).Stop(ctx)
}

// unusedIPV4 finds the next unused or expired IP address in the pool.
// IP addresses in the pool should be reused if they haven't been used for some period of time.
// reuseDeadline is the time before which addresses are considered to be expired.
// So if addresses are being reused after they haven't been used for 24 hours say, reuseDeadline
// would be 24 hours ago.
func (ps *consensusPerPeerState) unusedIPV4(ipset *netipx.IPSet, reuseDeadline time.Time) (netip.Addr, bool, string, error) {
	// If we want to have a random IP choice behavior we could make that work with the state machine by doing something like
	// passing the randomly chosen IP into the state machine call (so replaying logs would still be deterministic).
	for _, r := range ipset.Ranges() {
		ip := r.From()
		toIP := r.To()
		if !ip.IsValid() || !toIP.IsValid() {
			continue
		}
		for toIP.Compare(ip) != -1 {
			ww, ok := ps.addrToDomain.Lookup(ip)
			if !ok {
				return ip, false, "", nil
			}
			if ww.LastUsed.Before(reuseDeadline) {
				return ip, true, ww.Domain, nil
			}
			ip = ip.Next()
		}
	}
	return netip.Addr{}, false, "", errors.New("ip pool exhausted")
}

// IPForDomain is part of the IPPool interface. It returns an IP address for the given domain for the given node
// allocating an IP address from the pool if we haven't already.
func (ipp *ConsensusIPPool) IPForDomain(nid tailcfg.NodeID, domain string) (netip.Addr, error) {
	now := time.Now()
	args := checkoutAddrArgs{
		NodeID:        nid,
		Domain:        domain,
		ReuseDeadline: now.Add(-48 * time.Hour), // TODO (fran) is this appropriate? should it be configurable?
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
	result, err := ipp.consensus.ExecuteCommand(c)
	if err != nil {
		log.Printf("IPForDomain: raft error executing command: %v", err)
		return netip.Addr{}, err
	}
	if result.Err != nil {
		log.Printf("IPForDomain: error returned from state machine: %v", err)
		return netip.Addr{}, result.Err
	}
	var addr netip.Addr
	err = json.Unmarshal(result.Result, &addr)
	return addr, err
}

type markLastUsedArgs struct {
	NodeID    tailcfg.NodeID
	Addr      netip.Addr
	Domain    string
	UpdatedAt time.Time
}

// executeMarkLastUsed parses a markLastUsed log entry and applies it.
func (ipp *ConsensusIPPool) executeMarkLastUsed(bs []byte) tsconsensus.CommandResult {
	var args markLastUsedArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	err = ipp.applyMarkLastUsed(args.NodeID, args.Addr, args.Domain, args.UpdatedAt)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	return tsconsensus.CommandResult{}
}

// applyMarkLastUsed applies the arguments from the log entry to the state. It updates an entry in the AddrToDomain
// map with a new LastUsed timestamp.
// applyMarkLastUsed is not safe for concurrent access. It's only called from raft which will
// not call it concurrently.
func (ipp *ConsensusIPPool) applyMarkLastUsed(from tailcfg.NodeID, addr netip.Addr, domain string, updatedAt time.Time) error {
	ps, ok := ipp.perPeerMap.Load(from)
	if !ok {
		// There's nothing to mark. But this is unexpected, because we mark last used after we do things with peer state.
		log.Printf("applyMarkLastUsed: could not find peer state, nodeID: %s", from)
		return nil
	}
	ww, ok := ps.addrToDomain.Lookup(addr)
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
	ps.addrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), ww)
	return nil
}

// markLastUsed executes a markLastUsed command on the leader with raft.
func (ipp *ConsensusIPPool) markLastUsed(nid tailcfg.NodeID, addr netip.Addr, domain string, lastUsed time.Time) error {
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
	c := tsconsensus.Command{
		Name: "markLastUsed",
		Args: bs,
	}
	result, err := ipp.consensus.ExecuteCommand(c)
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

// executeCheckoutAddr parses a checkoutAddr raft log entry and applies it.
func (ipp *ConsensusIPPool) executeCheckoutAddr(bs []byte) tsconsensus.CommandResult {
	var args checkoutAddrArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	addr, err := ipp.applyCheckoutAddr(args.NodeID, args.Domain, args.ReuseDeadline, args.UpdatedAt)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	resultBs, err := json.Marshal(addr)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	return tsconsensus.CommandResult{Result: resultBs}
}

// applyCheckoutAddr finds the IP address for a nid+domain
// Each nid can use all of the addresses in the pool.
// updatedAt is the current time, the time at which we are wanting to get a new IP address.
// reuseDeadline is the time before which addresses are considered to be expired.
// So if addresses are being reused after they haven't been used for 24 hours say updatedAt would be now
// and reuseDeadline would be 24 hours ago.
// It is not safe for concurrent access (it's only called from raft, which will not call concurrently
// so that's fine).
func (ipp *ConsensusIPPool) applyCheckoutAddr(nid tailcfg.NodeID, domain string, reuseDeadline, updatedAt time.Time) (netip.Addr, error) {
	ps, _ := ipp.perPeerMap.LoadOrStore(nid, &consensusPerPeerState{
		addrToDomain: &bart.Table[whereWhen]{},
	})
	if existing, ok := ps.domainToAddr[domain]; ok {
		ww, ok := ps.addrToDomain.Lookup(existing)
		if ok {
			ww.LastUsed = updatedAt
			ps.addrToDomain.Insert(netip.PrefixFrom(existing, existing.BitLen()), ww)
			return existing, nil
		}
		log.Printf("applyCheckoutAddr: data out of sync, allocating new IP")
	}
	addr, wasInUse, previousDomain, err := ps.unusedIPV4(ipp.IPSet, reuseDeadline)
	if err != nil {
		return netip.Addr{}, err
	}
	mak.Set(&ps.domainToAddr, domain, addr)
	if wasInUse {
		delete(ps.domainToAddr, previousDomain)
	}
	ps.addrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), whereWhen{Domain: domain, LastUsed: updatedAt})
	return addr, nil
}

// Apply is part of the raft.FSM interface. It takes an incoming log entry and applies it to the state.
func (ipp *ConsensusIPPool) Apply(l *raft.Log) any {
	var c tsconsensus.Command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		panic(fmt.Sprintf("failed to unmarshal command: %s", err.Error()))
	}
	switch c.Name {
	case "checkoutAddr":
		return ipp.executeCheckoutAddr(c.Args)
	case "markLastUsed":
		return ipp.executeMarkLastUsed(c.Args)
	default:
		panic(fmt.Sprintf("unrecognized command: %s", c.Name))
	}
}

// commandExecutor is an interface covering the routing parts of consensus
// used to allow a fake in the tests
type commandExecutor interface {
	ExecuteCommand(tsconsensus.Command) (tsconsensus.CommandResult, error)
}
