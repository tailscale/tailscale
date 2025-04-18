package ippool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

/*
	TODO(fran)

An ConsensusIPPool is a group of one or more IPV4 ranges from which individual IPV4 addresses can be
checked out.

natc-consensus provides per domain router functionality for a tailnet.
  - when a node does a dns lookup for a domain the natc-consensus handles, natc-consensus asks ConsensusIPPool for an IP address
    for that node and domain. When ConsensusIPPool
  - when a node sends traffic to the IP address it has for a domain, natc-consensus asks ConsensusIPPool which domain that traffic
    is for.
  - when an IP address hasn't been used for a while ConsensusIPPool forgets about that node-ip-domain mapping and may provide
    that IP address to that node in response to a subsequent DNS request.

The pool is distributed across servers in a cluster, to provide high availability.

Each tailcfg.NodeID has the full range available. The same IPV4 address will be provided to different nodes.

ConsensusIPPool will maintain the node-ip-domain mapping until it expires, and won't hand out the IP address to that node
again while it maintains the mapping.

Reading from the pool is fast, writing to the pool is slow. Because reads can be done in memory on the server that got
the traffic, but writes must be sent to the consensus peers.

To handle expiry we write on reads, to update the last-used-date, but we do that after we've returned a response.

# ConsensusIPPool.DomainForIP gets the domain associated with a previous IP checkout for a node

ConsensusIPPool.IPForDomain gets an IP address for the node+domain. It will return an IP address from any existing mapping,
or it may create a mapping with a new unused IP address.
*/
type ConsensusIPPool struct {
	IPSet      *netipx.IPSet
	perPeerMap syncs.Map[tailcfg.NodeID, *consensusPerPeerState]
	consensus  commandExecutor
}

func (ipp *ConsensusIPPool) DomainForIP(from tailcfg.NodeID, addr netip.Addr, updatedAt time.Time) (string, bool) {
	// TODO (fran) lock?
	pm, ok := ipp.perPeerMap.Load(from)
	if !ok {
		log.Printf("DomainForIP: peer state absent for: %d", from)
		return "", false
	}
	ww, ok := pm.AddrToDomain.Lookup(addr)
	if !ok {
		log.Printf("DomainForIP: peer state doesn't recognize domain")
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

type markLastUsedArgs struct {
	NodeID    tailcfg.NodeID
	Addr      netip.Addr
	Domain    string
	UpdatedAt time.Time
}

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

func (ipp *ConsensusIPPool) applyMarkLastUsed(from tailcfg.NodeID, addr netip.Addr, domain string, updatedAt time.Time) error {
	// TODO (fran) lock?
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
	DomainToAddr map[string]netip.Addr
	AddrToDomain *bart.Table[whereWhen]
	mu           sync.Mutex // not jsonified
}

func (ipp *ConsensusIPPool) StopConsensus(ctx context.Context) error {
	return (ipp.consensus).(*tsconsensus.Consensus).Stop(ctx)
}

// unusedIPV4 finds the next unused or expired IP address in the pool.
// IP addresses in the pool should be reused if they haven't been used for some period of time.
// reuseDeadline is the time before which addresses are considered to be expired.
// So if addresses are being reused after they haven't been used for 24 hours say, reuseDeadline
// would be 24 hours ago.
func (ps *consensusPerPeerState) unusedIPV4(ipset *netipx.IPSet, reuseDeadline time.Time) (netip.Addr, bool, string, error) {
	// TODO (fran) here we iterate through each ip within the ranges until we find one that's unused or expired
	// if we want to have a random ip choice behavior we could make that work with the state machine by doing something like
	// passing the randomly chosen ip into the state machine call (so replaying logs would still be deterministic)
	for _, r := range ipset.Ranges() {
		ip := r.From()
		toIP := r.To()
		if !ip.IsValid() || !toIP.IsValid() {
			continue
		}
		for toIP.Compare(ip) != -1 {
			ww, ok := ps.AddrToDomain.Lookup(ip)
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

func (ipp *ConsensusIPPool) IPForDomain(nid tailcfg.NodeID, domain string) (netip.Addr, error) {
	now := time.Now()
	args := checkoutAddrArgs{
		NodeID:        nid,
		Domain:        domain,
		ReuseDeadline: now.Add(-48 * time.Hour), // TODO (fran) is this good? should it be configurable?
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
func (ipp *ConsensusIPPool) applyCheckoutAddr(nid tailcfg.NodeID, domain string, reuseDeadline, updatedAt time.Time) (netip.Addr, error) {
	// TODO (fran) lock and unlock (we need to right?)
	pm, _ := ipp.perPeerMap.LoadOrStore(nid, &consensusPerPeerState{
		AddrToDomain: &bart.Table[whereWhen]{},
	})
	if existing, ok := pm.DomainToAddr[domain]; ok {
		// TODO (fran) handle error case where this doesn't exist
		ww, _ := pm.AddrToDomain.Lookup(existing)
		ww.LastUsed = updatedAt
		pm.AddrToDomain.Insert(netip.PrefixFrom(existing, existing.BitLen()), ww)
		return existing, nil
	}
	addr, wasInUse, previousDomain, err := pm.unusedIPV4(ipp.IPSet, reuseDeadline)
	if err != nil {
		return netip.Addr{}, err
	}
	mak.Set(&pm.DomainToAddr, domain, addr)
	if wasInUse {
		delete(pm.DomainToAddr, previousDomain)
	}
	pm.AddrToDomain.Insert(netip.PrefixFrom(addr, addr.BitLen()), whereWhen{Domain: domain, LastUsed: updatedAt})
	return addr, nil
}

// fulfil the raft lib functional state machine interface
func (ipp *ConsensusIPPool) Apply(l *raft.Log) interface{} {
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

// TODO(fran) what exactly would we gain by implementing Snapshot and Restore?
func (ipp *ConsensusIPPool) Snapshot() (raft.FSMSnapshot, error) {
	return nil, nil
}

func (ipp *ConsensusIPPool) Restore(rc io.ReadCloser) error {
	return nil
}

// commandExecutor is an interface covering the routing parts of consensus
// used to allow a fake in the tests
type commandExecutor interface {
	ExecuteCommand(tsconsensus.Command) (tsconsensus.CommandResult, error)
}
