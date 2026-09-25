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
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

type appAddr struct {
	app         string
	addr        netip.Addr
	expiryEntry *list.Element
}

func (c *connector) handleTransitIPRequest(n tailcfg.NodeView, peerV4 netip.Addr, peerV6 netip.Addr, tipr TransitIPRequest) TransitIPResponse {
	if tipr.TransitIP.Is4() != tipr.DestinationIP.Is4() {
		c.logf("[Unexpected] peer attempt to map a transit IP to dest IP did not have matching families: node: %s, tIPv4: %v dIPv4: %v",
			n.StableID(), tipr.TransitIP.Is4(), tipr.DestinationIP.Is4())
		return TransitIPResponse{Code: AddrFamilyMismatch, Message: addrFamilyMismatchMessage}
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
	peerMap[tipr.TransitIP] = appAddr{addr: tipr.DestinationIP, app: tipr.App, expiryEntry: elem}
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
	return c.lookupAddrBySrcIPAndTransitIP(srcIP, transitIP)
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

// packetFilterAllow returns true if the provided packet has a Src that is in
// the configured transit IP range for this connector, false otherwise.
func (c *connector) packetFilterAllow(p packet.Parsed) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ipSets := c.getIPSets()
	if ipSets.v4Transit != nil && ipSets.v4Transit.Contains(p.Dst.Addr()) {
		return true, packetFilterAllowReason
	}
	if ipSets.v6Transit != nil && ipSets.v6Transit.Contains(p.Dst.Addr()) {
		return true, packetFilterAllowReason
	}
	return false, ""
}

func (c *connector) lookupAddrBySrcIPAndTransitIP(srcIP, transitIP netip.Addr) (netip.Addr, bool) {
	m, ok := c.transitIPs[srcIP]
	if !ok || m == nil {
		return netip.Addr{}, false
	}
	v, ok := m[transitIP]
	return v.addr, ok
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
}
