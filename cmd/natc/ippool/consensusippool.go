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
	"time"

	"github.com/hashicorp/raft"
	"go4.org/netipx"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsconsensus"
	"tailscale.com/tsnet"
	"tailscale.com/util/mak"
)

// ConsensusIPPool implements an [IPPool] that is distributed among members of a cluster for high availability.
// Writes are directed to a leader among the cluster and are slower than reads, reads are performed locally
// using information replicated from the leader.
// The cluster maintains consistency, reads can be stale and writes can be unavailable if sufficient cluster
// peers are unavailable.
type ConsensusIPPool struct {
	IPSet                 *netipx.IPSet
	perPeerMap            *syncs.Map[tailcfg.NodeID, *consensusPerPeerState]
	consensus             commandExecutor
	clusterController     clusterController
	unusedAddressLifetime time.Duration
}

func NewConsensusIPPool(ipSet *netipx.IPSet) *ConsensusIPPool {
	return &ConsensusIPPool{
		unusedAddressLifetime: 48 * time.Hour, // TODO (fran) is this appropriate? should it be configurable?
		IPSet:                 ipSet,
		perPeerMap:            &syncs.Map[tailcfg.NodeID, *consensusPerPeerState]{},
	}
}

// IPForDomain looks up or creates an IP address allocation for the tailcfg.NodeID and domain pair.
// If no address association is found, one is allocated from the range of free addresses for this tailcfg.NodeID.
// If no more address are available, an error is returned.
func (ipp *ConsensusIPPool) IPForDomain(nid tailcfg.NodeID, domain string) (netip.Addr, error) {
	now := time.Now()
	// Check local state; local state may be stale. If we have an IP for this domain, and we are not
	// close to the expiry time for the domain, it's safe to return what we have.
	ps, psFound := ipp.perPeerMap.Load(nid)
	if psFound {
		if addr, addrFound := ps.domainToAddr[domain]; addrFound {
			if ww, wwFound := ps.addrToDomain.Load(addr); wwFound {
				if !isCloseToExpiry(ww.LastUsed, now, ipp.unusedAddressLifetime) {
					ipp.fireAndForgetMarkLastUsed(nid, addr, ww, now)
					return addr, nil
				}
			}
		}
	}

	// go via consensus
	args := checkoutAddrArgs{
		NodeID:        nid,
		Domain:        domain,
		ReuseDeadline: now.Add(-1 * ipp.unusedAddressLifetime),
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

// DomainForIP looks up the domain associated with a tailcfg.NodeID and netip.Addr pair.
// If there is no association, the result is empty and ok is false.
func (ipp *ConsensusIPPool) DomainForIP(from tailcfg.NodeID, addr netip.Addr, updatedAt time.Time) (string, bool) {
	// Look in local state, to save a consensus round trip; local state may be stale.
	//
	// The only time we expect ordering of commands to matter to clients is on first
	// connection to a domain. In that case it may be that although we don't find the
	// domain in our local state, it is in fact in the state of the state machine (ie
	// the client did a DNS lookup, and we responded with an IP and _should_ know that
	// domain when the TCP connection for that IP arrives.)
	//
	// So it's ok to return local state, unless local state doesn't recognize the domain,
	// in which case we should check the consensus state machine to know for sure.
	var domain string
	ww, ok := ipp.domainLookup(from, addr)
	if ok {
		domain = ww.Domain
	} else {
		d, err := ipp.readDomainForIP(from, addr)
		if err != nil {
			log.Printf("error reading domain from consensus: %v", err)
			return "", false
		}
		domain = d
	}
	if domain == "" {
		log.Printf("did not find domain for node: %v, addr: %s", from, addr)
		return "", false
	}
	ipp.fireAndForgetMarkLastUsed(from, addr, ww, updatedAt)
	return domain, true
}

func (ipp *ConsensusIPPool) fireAndForgetMarkLastUsed(from tailcfg.NodeID, addr netip.Addr, ww whereWhen, updatedAt time.Time) {
	window := 5 * time.Minute
	if updatedAt.Sub(ww.LastUsed).Abs() < window {
		return
	}
	go func() {
		err := ipp.markLastUsed(from, addr, ww.Domain, updatedAt)
		if err != nil {
			log.Printf("error marking last used: %v", err)
		}
	}()
}

func (ipp *ConsensusIPPool) domainLookup(from tailcfg.NodeID, addr netip.Addr) (whereWhen, bool) {
	ps, ok := ipp.perPeerMap.Load(from)
	if !ok {
		log.Printf("domainLookup: peer state absent for: %d", from)
		return whereWhen{}, false
	}
	ww, ok := ps.addrToDomain.Load(addr)
	if !ok {
		log.Printf("domainLookup: peer state doesn't recognize addr: %s", addr)
		return whereWhen{}, false
	}
	return ww, true
}

type ClusterOpts struct {
	Tag        string
	StateDir   string
	FollowOnly bool
}

// StartConsensus is part of the IPPool interface. It starts the raft background routines that handle consensus.
func (ipp *ConsensusIPPool) StartConsensus(ctx context.Context, ts *tsnet.Server, opts ClusterOpts) error {
	cfg := tsconsensus.DefaultConfig()
	cfg.ServeDebugMonitor = true
	cfg.StateDirPath = opts.StateDir
	cns, err := tsconsensus.Start(ctx, ts, ipp, tsconsensus.BootstrapOpts{
		Tag:        opts.Tag,
		FollowOnly: opts.FollowOnly,
	}, cfg)
	if err != nil {
		return err
	}
	ipp.consensus = cns
	ipp.clusterController = cns
	return nil
}

type whereWhen struct {
	Domain   string
	LastUsed time.Time
}

type consensusPerPeerState struct {
	domainToAddr map[string]netip.Addr
	addrToDomain *syncs.Map[netip.Addr, whereWhen]
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
			ww, ok := ps.addrToDomain.Load(ip)
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

// isCloseToExpiry returns true if the lastUsed and now times are more than
// half the lifetime apart
func isCloseToExpiry(lastUsed, now time.Time, lifetime time.Duration) bool {
	return now.Sub(lastUsed).Abs() > (lifetime / 2)
}

type readDomainForIPArgs struct {
	NodeID tailcfg.NodeID
	Addr   netip.Addr
}

// executeReadDomainForIP parses a readDomainForIP log entry and applies it.
func (ipp *ConsensusIPPool) executeReadDomainForIP(bs []byte) tsconsensus.CommandResult {
	var args readDomainForIPArgs
	err := json.Unmarshal(bs, &args)
	if err != nil {
		return tsconsensus.CommandResult{Err: err}
	}
	return ipp.applyReadDomainForIP(args.NodeID, args.Addr)
}

func (ipp *ConsensusIPPool) applyReadDomainForIP(from tailcfg.NodeID, addr netip.Addr) tsconsensus.CommandResult {
	domain := func() string {
		ps, ok := ipp.perPeerMap.Load(from)
		if !ok {
			return ""
		}
		ww, ok := ps.addrToDomain.Load(addr)
		if !ok {
			return ""
		}
		return ww.Domain
	}()
	resultBs, err := json.Marshal(domain)
	return tsconsensus.CommandResult{Result: resultBs, Err: err}
}

// readDomainForIP executes a readDomainForIP command on the leader with raft.
func (ipp *ConsensusIPPool) readDomainForIP(nid tailcfg.NodeID, addr netip.Addr) (string, error) {
	args := readDomainForIPArgs{
		NodeID: nid,
		Addr:   addr,
	}
	bs, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	c := tsconsensus.Command{
		Name: "readDomainForIP",
		Args: bs,
	}
	result, err := ipp.consensus.ExecuteCommand(c)
	if err != nil {
		log.Printf("readDomainForIP: raft error executing command: %v", err)
		return "", err
	}
	if result.Err != nil {
		log.Printf("readDomainForIP: error returned from state machine: %v", err)
		return "", result.Err
	}
	var domain string
	err = json.Unmarshal(result.Result, &domain)
	return domain, err
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
	ww, ok := ps.addrToDomain.Load(addr)
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
	ps.addrToDomain.Store(addr, ww)
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
	ps, ok := ipp.perPeerMap.Load(nid)
	if !ok {
		ps = &consensusPerPeerState{
			addrToDomain: &syncs.Map[netip.Addr, whereWhen]{},
		}
		ipp.perPeerMap.Store(nid, ps)
	}
	if existing, ok := ps.domainToAddr[domain]; ok {
		ww, ok := ps.addrToDomain.Load(existing)
		if ok {
			ww.LastUsed = updatedAt
			ps.addrToDomain.Store(existing, ww)
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
	ps.addrToDomain.Store(addr, whereWhen{Domain: domain, LastUsed: updatedAt})
	return addr, nil
}

// Apply is part of the raft.FSM interface. It takes an incoming log entry and applies it to the state.
func (ipp *ConsensusIPPool) Apply(lg *raft.Log) any {
	var c tsconsensus.Command
	if err := json.Unmarshal(lg.Data, &c); err != nil {
		panic(fmt.Sprintf("failed to unmarshal command: %s", err.Error()))
	}
	switch c.Name {
	case "checkoutAddr":
		return ipp.executeCheckoutAddr(c.Args)
	case "markLastUsed":
		return ipp.executeMarkLastUsed(c.Args)
	case "readDomainForIP":
		return ipp.executeReadDomainForIP(c.Args)
	default:
		panic(fmt.Sprintf("unrecognized command: %s", c.Name))
	}
}

// commandExecutor is an interface covering the routing parts of consensus
// used to allow a fake in the tests
type commandExecutor interface {
	ExecuteCommand(tsconsensus.Command) (tsconsensus.CommandResult, error)
}

type clusterController interface {
	GetClusterConfiguration() (raft.Configuration, error)
	DeleteClusterServer(id raft.ServerID) (uint64, error)
}

// GetClusterConfiguration gets the consensus implementation's cluster configuration
func (ipp *ConsensusIPPool) GetClusterConfiguration() (raft.Configuration, error) {
	return ipp.clusterController.GetClusterConfiguration()
}

// DeleteClusterServer removes a server from the consensus implementation's cluster configuration
func (ipp *ConsensusIPPool) DeleteClusterServer(id raft.ServerID) (uint64, error) {
	return ipp.clusterController.DeleteClusterServer(id)
}
