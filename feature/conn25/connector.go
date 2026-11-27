// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"container/list"
	"context"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/net/routelimits"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
)

type appAddr struct {
	app  string
	addr netip.Addr
	// ports are the protocol and port combinations the peer was permitted to
	// reach through app at the moment it registered this mapping.
	ports       views.Slice[tailcfg.ProtoPortRange]
	expiryEntry *list.Element
}

func (c *connector) handleTransitIPRequest(
	n tailcfg.NodeView,
	peerV4 netip.Addr,
	peerV6 netip.Addr,
	tipr TransitIPRequest,
	ports views.Slice[tailcfg.ProtoPortRange],
) TransitIPResponse {
	if tipr.TransitIP.Is4() != tipr.DestinationIP.Is4() {
		c.logf("[Unexpected] peer attempt to map a transit IP to dest IP did not have matching families: node: %s, tIPv4: %v dIPv4: %v",
			n.StableID(), tipr.TransitIP.Is4(), tipr.DestinationIP.Is4())
		return TransitIPResponse{Code: AddrFamilyMismatch, Message: addrFamilyMismatchMessage}
	}

	if c.destIsDisallowed(tipr.DestinationIP) {
		return TransitIPResponse{Code: DisallowedDestination, Message: disallowedDestinationMessage}
	}

	// The transit address has to come from a transit IP pool we're configured with.
	if !c.transitIPInPool(tipr.TransitIP) {
		c.logf("[Unexpected] peer attempt to map a transit IP outside of the configured pools: node: %s, IP: %v",
			n.StableID(), tipr.TransitIP)
		return TransitIPResponse{Code: TransitIPNotInPool, Message: transitIPNotInPoolMessage}
	}

	// Datapath lookups only have access to the peer IP, and that will match the family
	// of the transit IP, so we need to store v4 and v6 mappings separately.
	var peerAddr netip.Addr
	if tipr.TransitIP.Is4() {
		peerAddr = peerV4
	} else {
		peerAddr = peerV6
	}

	// If we couldn't find a matching family, return an error.
	if !peerAddr.IsValid() {
		c.logf("[Unexpected] peer attempt to map a transit IP did not have a matching address family: node: %s, IPv4: %v",
			n.StableID(), tipr.TransitIP.Is4())
		return TransitIPResponse{NoMatchingPeerIPFamily, noMatchingPeerIPFamilyMessage}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transitIPs == nil {
		c.transitIPs = make(map[netip.Addr]map[netip.Addr]appAddr)
	}
	peerMap, ok := c.transitIPs[peerAddr]
	if !ok {
		peerMap = make(map[netip.Addr]appAddr)
		c.transitIPs[peerAddr] = peerMap
	}
	// if there's already an entry for this peer+transitIP, clean up the expiryQueue entry
	if prev, ok := peerMap[tipr.TransitIP]; ok && prev.expiryEntry != nil {
		c.expiryQueue.Remove(prev.expiryEntry)
	}
	// create a new expiryQueue entry
	elem := c.expiryQueue.PushBack(&transitIPExpiryEntry{
		peerIP:    peerAddr,
		transitIP: tipr.TransitIP,
		createdAt: c.clock.Now(),
	})
	peerMap[tipr.TransitIP] = appAddr{addr: tipr.DestinationIP, app: tipr.App, ports: ports, expiryEntry: elem}
	return TransitIPResponse{}
}

// connectorTransitIPExpiry is the minimum length of time a peer+transitIP -> dstIP mapping will be held in the connector.
// The longer this time is the larger the map will be in memory.
// The shorter this time is the more often a client will try to use a mapping, find it doesn't exist anymore and have to re-register.
// We are not (yet 2026-08-12) tracking either of those things, this is a guess at a reasonable duration.
const connectorTransitIPExpiry = time.Hour

type connector struct {
	logf      logger.Logf
	getIPSets func() ipSets
	clock     tstime.Clock

	// Remember to add new fields to [connector.reset] if needed.
	mu sync.Mutex // protects the fields below
	// tokenSecret is the random secret used to mint and verify tokens in TransitIPRequests.
	// It is generated in memory at creation, rotated on [connector.reset] (ie on profile change), and not persisted.
	tokenSecret [tokenSecretLen]byte
	// transitIPs is a map of connector client peer IP -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	// Note that each peer could potentially have two maps: one for its IPv4 address, and one for its IPv6 address. The transit IPs map for a given peer IP will contain transit IPs of the same family as the peer's IP.
	transitIPs map[netip.Addr]map[netip.Addr]appAddr
	// expiryQueue is processed by the goroutine from [connector.startExpirySweeper] so
	// that transitIPs doesn't grow indefinitely.
	expiryQueue *list.List
}

type transitIPExpiryEntry struct {
	peerIP    netip.Addr
	transitIP netip.Addr
	createdAt time.Time
}

// realIPForTransitIPConnection is part of the implementation of the [Conn25Datapath] interface for dataflow lookups.
// See also [Conn25Datapath.ConnectorRealIPForTransitIPConnection].
func (c *connector) realIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	aa, ok := c.lookupAppAddrBySrcIPAndTransitIPLocked(srcIP, transitIP)
	return aa.addr, ok
}

// transitIPInPool reports whether tip is within the transit IP pool of its
// address family that this connector is configured with.
func (c *connector) transitIPInPool(tip netip.Addr) bool {
	ipSets := c.getIPSets()
	if tip.Is4() {
		return ipSets.v4Transit != nil && ipSets.v4Transit.Contains(tip)
	}
	return ipSets.v6Transit != nil && ipSets.v6Transit.Contains(tip)
}

func (c *connector) destIsDisallowed(dst netip.Addr) bool {
	if routelimits.IsDisallowed(dst) || c.destinationInPools(dst) {
		return true
	}
	// TODO(tailscale/corp#50542): remove this condition when we have a configurable check
	return dst.IsPrivate()
}

// destinationInPool reports whether dst is within one of the magic or transit IP pools,
// of its address family, that this connector is configured with. Forwarding to such
// an address would route back into conn25's own mapping layer rather than out to an app.
func (c *connector) destinationInPools(dst netip.Addr) bool {
	ipSets := c.getIPSets()
	magic, transit := ipSets.v6Magic, ipSets.v6Transit
	if dst.Unmap().Is4() {
		magic, transit = ipSets.v4Magic, ipSets.v4Transit
	}
	return (magic != nil && magic.Contains(dst)) || (transit != nil && transit.Contains(dst))
}

// linkLocalAllow returns true if the provided packet has a Dst that is in
// the configured transit IP range for this connector, false otherwise.
//
// It only exempts the packet from the filter's blanket drop of link-local
// destinations; it does not accept it. Whether the connector accepts the
// packet is decided separately by [connector.ingressAllow], which both hooks
// a packet to a transit IP has to get through.
func (c *connector) linkLocalAllow(p packet.Parsed) (bool, string) {
	if c.transitIPInPool(p.Dst.Addr()) {
		return true, connectorTransitIPReason
	}
	return false, ""
}

// ingressAllow reports whether p, a packet arriving from a peer, may be
// accepted by this connector. It may if p is addressed to an address in a
// configured transit IP pool and either the peer has no mapping registered for
// that address, or the grant it registered the mapping under permits p's
// protocol and destination port.
//
// Packets for an unregistered mapping are accepted here so that the datapath
// can drop them itself and answer with the TSMP message that prompts the
// client to re-register (see [datapathHandler.HandlePacketFromWireGuard]).
// Nothing is forwarded on their behalf.
//
// The permitted protocols and ports are the ones the peer held when it
// registered the mapping. A grant that is tightened afterwards takes effect
// when the mapping is re-registered, at the latest [connectorTransitIPExpiry]
// after it was last registered.
func (c *connector) ingressAllow(p packet.Parsed) (bool, string) {
	if !c.transitIPInPool(p.Dst.Addr()) {
		return false, ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	aa, ok := c.lookupAppAddrBySrcIPAndTransitIPLocked(p.Src.Addr(), p.Dst.Addr())
	if !ok {
		return true, connectorUnmappedReason
	}
	return protoPortRangesAllow(aa.ports, p)
}

// lookupAppAddrBySrcIPAndTransitIPLocked returns the mapping the peer at srcIP
// registered for transitIP, or (zero, false) if it registered none.
// c.mu must be held.
func (c *connector) lookupAppAddrBySrcIPAndTransitIPLocked(srcIP, transitIP netip.Addr) (appAddr, bool) {
	m, ok := c.transitIPs[srcIP]
	if !ok || m == nil {
		return appAddr{}, false
	}
	v, ok := m[transitIP]
	return v, ok
}

// expireTransitIPs expires entries in the connector's transitIPs map that are
// past their expiry time.
// While the client keeps track of the datapath flow table and makes sure not
// to expire state for flows that are in use, the connector just expires
// peer+transitIP -> dstIP state at minimum 1 hour [connectorTransitIPExpiry]
// after it is registered.
// If a client tries to use a mapping that is expired the connector will send a
// TSMP error and the client will reregister the mapping.
// If this causes too much reregistry we can extend the expiry time or we may
// have to track flows or similar.
func (c *connector) expireTransitIPs(now time.Time) int {
	removed := 0

	// doChunk takes the chunk size and returns the number of removed entries and
	// whether there's still work to do.
	// Used to allow other goroutines a chance to grab the mutex while we work.
	doChunk := func(n int) (int, bool) {
		nRemoved := 0
		c.mu.Lock()
		defer c.mu.Unlock()
		for i := 0; i < n; i++ {
			front := c.expiryQueue.Front()
			if front == nil {
				return nRemoved, true
			}
			e := front.Value.(*transitIPExpiryEntry)
			if now.Sub(e.createdAt) < connectorTransitIPExpiry {
				// the list is ordered by createdAt there will be no entries to expire after this
				return nRemoved, true
			}
			c.expiryQueue.Remove(front)
			peerMap, ok := c.transitIPs[e.peerIP]
			if !ok {
				continue
			}
			delete(peerMap, e.transitIP)
			nRemoved++
			if len(peerMap) == 0 {
				delete(c.transitIPs, e.peerIP)
			}
		}
		return nRemoved, false
	}

	// handle at most 100,000 entries, don't just keep going if we have an
	// unexpectedly large number of expiries, we will handle the backlog over time.
	for i := 0; i < 1000; i++ {
		nRemoved, finished := doChunk(100)
		removed += nRemoved
		if finished {
			break
		}
	}
	return removed
}

func (c *connector) startExpirySweeper(ctx context.Context) {
	ticker, tickerCh := c.clock.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tickerCh:
				c.expireTransitIPs(c.clock.Now())
			}
		}
	}()
}

// reset clears all internal state of [connector], that are not configuration
// passed into it.
func (c *connector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.transitIPs = make(map[netip.Addr]map[netip.Addr]appAddr)
	c.expiryQueue = list.New()
	// old tokens should no longer verify
	c.tokenSecret = newTokenSecret()
}
