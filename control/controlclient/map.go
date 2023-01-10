// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// mapSession holds the state over a long-polled "map" request to the
// control plane.
//
// It accepts incremental tailcfg.MapResponse values to
// netMapForResponse and returns fully inflated NetworkMaps, filling
// in the omitted data implicit from prior MapResponse values from
// within the same session (the same long-poll HTTP response to the
// one MapRequest).
type mapSession struct {
	// Immutable fields.
	privateNodeKey         key.NodePrivate
	logf                   logger.Logf
	vlogf                  logger.Logf
	machinePubKey          key.MachinePublic
	keepSharerAndUserSplit bool // see Options.KeepSharerAndUserSplit

	// Fields storing state over the course of multiple MapResponses.
	lastNode               *tailcfg.Node
	lastDNSConfig          *tailcfg.DNSConfig
	lastDERPMap            *tailcfg.DERPMap
	lastUserProfile        map[tailcfg.UserID]tailcfg.UserProfile
	lastPacketFilterRules  views.Slice[tailcfg.FilterRule]
	lastParsedPacketFilter []filter.Match
	lastSSHPolicy          *tailcfg.SSHPolicy
	collectServices        bool
	previousPeers          []*tailcfg.Node // for delta-purposes
	lastDomain             string
	lastDomainAuditLogID   string
	lastHealth             []string
	lastPopBrowserURL      string
	stickyDebug            tailcfg.Debug // accumulated opt.Bool values
	lastTKAInfo            *tailcfg.TKAInfo
	previouslyExpired      map[tailcfg.StableNodeID]bool // to avoid log spam

	// clockDelta stores the delta between the current time and the time
	// received from control such that:
	//    time.Now().Add(clockDelta) == MapResponse.ControlTime
	clockDelta time.Duration

	// netMapBuilding is non-nil during a netmapForResponse call,
	// containing the value to be returned, once fully populated.
	netMapBuilding *netmap.NetworkMap
}

func newMapSession(privateNodeKey key.NodePrivate) *mapSession {
	ms := &mapSession{
		privateNodeKey:    privateNodeKey,
		logf:              logger.Discard,
		vlogf:             logger.Discard,
		lastDNSConfig:     new(tailcfg.DNSConfig),
		lastUserProfile:   map[tailcfg.UserID]tailcfg.UserProfile{},
		previouslyExpired: map[tailcfg.StableNodeID]bool{},
	}
	return ms
}

func (ms *mapSession) addUserProfile(userID tailcfg.UserID) {
	nm := ms.netMapBuilding
	if _, dup := nm.UserProfiles[userID]; dup {
		// Already populated it from a previous peer.
		return
	}
	if up, ok := ms.lastUserProfile[userID]; ok {
		nm.UserProfiles[userID] = up
	}
}

// netmapForResponse returns a fully populated NetworkMap from a full
// or incremental MapResponse within the session, filling in omitted
// information from prior MapResponse values.
func (ms *mapSession) netmapForResponse(resp *tailcfg.MapResponse) *netmap.NetworkMap {
	undeltaPeers(resp, ms.previousPeers)
	ms.flagExpiredPeers(resp)

	ms.previousPeers = cloneNodes(resp.Peers) // defensive/lazy clone, since this escapes to who knows where
	for _, up := range resp.UserProfiles {
		ms.lastUserProfile[up.ID] = up
	}

	if resp.DERPMap != nil {
		ms.vlogf("netmap: new map contains DERP map")
		ms.lastDERPMap = resp.DERPMap
	}

	if pf := resp.PacketFilter; pf != nil {
		var err error
		ms.lastPacketFilterRules = views.SliceOf(pf)
		ms.lastParsedPacketFilter, err = filter.MatchesFromFilterRules(pf)
		if err != nil {
			ms.logf("parsePacketFilter: %v", err)
		}
	}
	if c := resp.DNSConfig; c != nil {
		ms.lastDNSConfig = c
	}
	if p := resp.SSHPolicy; p != nil {
		ms.lastSSHPolicy = p
	}

	if v, ok := resp.CollectServices.Get(); ok {
		ms.collectServices = v
	}
	if resp.Domain != "" {
		ms.lastDomain = resp.Domain
	}
	if resp.DomainDataPlaneAuditLogID != "" {
		ms.lastDomainAuditLogID = resp.DomainDataPlaneAuditLogID
	}
	if resp.Health != nil {
		ms.lastHealth = resp.Health
	}
	if resp.TKAInfo != nil {
		ms.lastTKAInfo = resp.TKAInfo
	}

	debug := resp.Debug
	if debug != nil {
		if debug.RandomizeClientPort {
			debug.SetRandomizeClientPort.Set(true)
		}
		if debug.ForceBackgroundSTUN {
			debug.SetForceBackgroundSTUN.Set(true)
		}
		copyDebugOptBools(&ms.stickyDebug, debug)
	} else if ms.stickyDebug != (tailcfg.Debug{}) {
		debug = new(tailcfg.Debug)
	}
	if debug != nil {
		copyDebugOptBools(debug, &ms.stickyDebug)
		if !debug.ForceBackgroundSTUN {
			debug.ForceBackgroundSTUN, _ = ms.stickyDebug.SetForceBackgroundSTUN.Get()
		}
		if !debug.RandomizeClientPort {
			debug.RandomizeClientPort, _ = ms.stickyDebug.SetRandomizeClientPort.Get()
		}
	}

	nm := &netmap.NetworkMap{
		NodeKey:           ms.privateNodeKey.Public(),
		PrivateKey:        ms.privateNodeKey,
		MachineKey:        ms.machinePubKey,
		Peers:             resp.Peers,
		UserProfiles:      make(map[tailcfg.UserID]tailcfg.UserProfile),
		Domain:            ms.lastDomain,
		DomainAuditLogID:  ms.lastDomainAuditLogID,
		DNS:               *ms.lastDNSConfig,
		PacketFilter:      ms.lastParsedPacketFilter,
		PacketFilterRules: ms.lastPacketFilterRules,
		SSHPolicy:         ms.lastSSHPolicy,
		CollectServices:   ms.collectServices,
		DERPMap:           ms.lastDERPMap,
		Debug:             debug,
		ControlHealth:     ms.lastHealth,
		TKAEnabled:        ms.lastTKAInfo != nil && !ms.lastTKAInfo.Disabled,
	}
	ms.netMapBuilding = nm

	if ms.lastTKAInfo != nil && ms.lastTKAInfo.Head != "" {
		if err := nm.TKAHead.UnmarshalText([]byte(ms.lastTKAInfo.Head)); err != nil {
			ms.logf("error unmarshalling TKAHead: %v", err)
			nm.TKAEnabled = false
		}
	}

	if resp.Node != nil {
		ms.lastNode = resp.Node
	}
	if node := ms.lastNode.Clone(); node != nil {
		nm.SelfNode = node
		nm.Expiry = node.KeyExpiry
		nm.Name = node.Name
		nm.Addresses = filterSelfAddresses(node.Addresses)
		nm.User = node.User
		if node.Hostinfo.Valid() {
			nm.Hostinfo = *node.Hostinfo.AsStruct()
		}
		if node.MachineAuthorized {
			nm.MachineStatus = tailcfg.MachineAuthorized
		} else {
			nm.MachineStatus = tailcfg.MachineUnauthorized
		}
	}

	ms.addUserProfile(nm.User)
	magicDNSSuffix := nm.MagicDNSSuffix()
	if nm.SelfNode != nil {
		nm.SelfNode.InitDisplayNames(magicDNSSuffix)
	}
	for _, peer := range resp.Peers {
		peer.InitDisplayNames(magicDNSSuffix)
		if !peer.Sharer.IsZero() {
			if ms.keepSharerAndUserSplit {
				ms.addUserProfile(peer.Sharer)
			} else {
				peer.User = peer.Sharer
			}
		}
		ms.addUserProfile(peer.User)
	}
	if DevKnob.ForceProxyDNS() {
		nm.DNS.Proxied = true
	}
	ms.netMapBuilding = nil
	return nm
}

// undeltaPeers updates mapRes.Peers to be complete based on the
// provided previous peer list and the PeersRemoved and PeersChanged
// fields in mapRes, as well as the PeerSeenChange and OnlineChange
// maps.
//
// It then also nils out the delta fields.
func undeltaPeers(mapRes *tailcfg.MapResponse, prev []*tailcfg.Node) {
	if len(mapRes.Peers) > 0 {
		// Not delta encoded.
		if !nodesSorted(mapRes.Peers) {
			log.Printf("netmap: undeltaPeers: MapResponse.Peers not sorted; sorting")
			sortNodes(mapRes.Peers)
		}
		return
	}

	var removed map[tailcfg.NodeID]bool
	if pr := mapRes.PeersRemoved; len(pr) > 0 {
		removed = make(map[tailcfg.NodeID]bool, len(pr))
		for _, id := range pr {
			removed[id] = true
		}
	}
	changed := mapRes.PeersChanged

	if !nodesSorted(changed) {
		log.Printf("netmap: undeltaPeers: MapResponse.PeersChanged not sorted; sorting")
		sortNodes(changed)
	}
	if !nodesSorted(prev) {
		// Internal error (unrelated to the network) if we get here.
		log.Printf("netmap: undeltaPeers: [unexpected] prev not sorted; sorting")
		sortNodes(prev)
	}

	newFull := prev
	if len(removed) > 0 || len(changed) > 0 {
		newFull = make([]*tailcfg.Node, 0, len(prev)-len(removed))
		for len(prev) > 0 && len(changed) > 0 {
			pID := prev[0].ID
			cID := changed[0].ID
			if removed[pID] {
				prev = prev[1:]
				continue
			}
			switch {
			case pID < cID:
				newFull = append(newFull, prev[0])
				prev = prev[1:]
			case pID == cID:
				newFull = append(newFull, changed[0])
				prev, changed = prev[1:], changed[1:]
			case cID < pID:
				newFull = append(newFull, changed[0])
				changed = changed[1:]
			}
		}
		newFull = append(newFull, changed...)
		for _, n := range prev {
			if !removed[n.ID] {
				newFull = append(newFull, n)
			}
		}
		sortNodes(newFull)
	}

	if len(mapRes.PeerSeenChange) != 0 || len(mapRes.OnlineChange) != 0 || len(mapRes.PeersChangedPatch) != 0 {
		peerByID := make(map[tailcfg.NodeID]*tailcfg.Node, len(newFull))
		for _, n := range newFull {
			peerByID[n.ID] = n
		}
		now := clockNow()
		for nodeID, seen := range mapRes.PeerSeenChange {
			if n, ok := peerByID[nodeID]; ok {
				if seen {
					n.LastSeen = &now
				} else {
					n.LastSeen = nil
				}
			}
		}
		for nodeID, online := range mapRes.OnlineChange {
			if n, ok := peerByID[nodeID]; ok {
				online := online
				n.Online = &online
			}
		}
		for _, ec := range mapRes.PeersChangedPatch {
			if n, ok := peerByID[ec.NodeID]; ok {
				if ec.DERPRegion != 0 {
					n.DERP = fmt.Sprintf("%s:%v", tailcfg.DerpMagicIP, ec.DERPRegion)
				}
				if ec.Endpoints != nil {
					n.Endpoints = ec.Endpoints
				}
				if ec.Key != nil {
					n.Key = *ec.Key
				}
				if ec.DiscoKey != nil {
					n.DiscoKey = *ec.DiscoKey
				}
				if v := ec.Online; v != nil {
					n.Online = ptrCopy(v)
				}
				if v := ec.LastSeen; v != nil {
					n.LastSeen = ptrCopy(v)
				}
				if v := ec.KeyExpiry; v != nil {
					n.KeyExpiry = *v
				}
				if v := ec.Capabilities; v != nil {
					n.Capabilities = *v
				}
				if v := ec.KeySignature; v != nil {
					n.KeySignature = v
				}
			}
		}
	}

	mapRes.Peers = newFull
	mapRes.PeersChanged = nil
	mapRes.PeersRemoved = nil
}

// For extra defense-in-depth, when we're testing expired nodes we check
// ControlTime against this 'epoch' (set to the approximate time that this code
// was written) such that if control (or Headscale, etc.) sends a ControlTime
// that's sufficiently far in the past, we can safely ignore it.
var flagExpiredPeersEpoch = time.Unix(1673373066, 0)

// If the offset between the current time and the time received from control is
// larger than this, we store an offset in our mapSession to adjust future
// clock timings.
const minClockDelta = 1 * time.Minute

// flagExpiredPeers updates mapRes.Peers, mutating all peers that have expired,
// taking into account any clock skew detected by using the ControlTime field
// in the MapResponse. We don't actually remove expired peers from the Peers
// array; instead, we clear some fields of the Node object, and set
// Node.Expired so other parts of the codebase can provide more clear error
// messages when attempting to e.g. ping an expired node.
//
// This is additionally a defense-in-depth against something going wrong with
// control such that we start seeing expired peers with a valid Endpoints or
// DERP field.
func (ms *mapSession) flagExpiredPeers(mapRes *tailcfg.MapResponse) {
	localNow := clockNow()

	// If we have a ControlTime field, update our delta.
	if mapRes.ControlTime != nil && !mapRes.ControlTime.IsZero() {
		delta := mapRes.ControlTime.Sub(localNow)
		if delta.Abs() > minClockDelta {
			ms.logf("[v1] netmap: flagExpiredPeers: setting clock delta to %v", delta)
			ms.clockDelta = delta
		} else {
			ms.clockDelta = 0
		}
	}

	// Adjust our current time by any saved delta to adjust for clock skew.
	controlNow := localNow.Add(ms.clockDelta)
	if controlNow.Before(flagExpiredPeersEpoch) {
		ms.logf("netmap: flagExpiredPeers: [unexpected] delta-adjusted current time is before hardcoded epoch; skipping")
		return
	}

	for _, peer := range mapRes.Peers {
		// Nodes that don't expire have KeyExpiry set to the zero time;
		// skip those and peers that are already marked as expired
		// (e.g. from control).
		if peer.KeyExpiry.IsZero() || peer.KeyExpiry.After(controlNow) {
			delete(ms.previouslyExpired, peer.StableID)
			continue
		} else if peer.Expired {
			continue
		}

		if !ms.previouslyExpired[peer.StableID] {
			ms.logf("[v1] netmap: flagExpiredPeers: clearing expired peer %v", peer.StableID)
			ms.previouslyExpired[peer.StableID] = true
		}

		// Actually mark the node as expired
		peer.Expired = true

		// Control clears the Endpoints and DERP fields of expired
		// nodes; do so here as well. The Expired bool is the correct
		// thing to set, but this replicates the previous behaviour.
		//
		// NOTE: this is insufficient to actually break connectivity,
		// since we discover endpoints via DERP, and due to DERP return
		// path optimization.
		peer.Endpoints = nil
		peer.DERP = ""

		// Defense-in-depth: break the node's public key as well, in
		// case something tries to communicate.
		peer.Key = key.NodePublicWithBadOldPrefix(peer.Key)
	}
}

// ptrCopy returns a pointer to a newly allocated shallow copy of *v.
func ptrCopy[T any](v *T) *T {
	if v == nil {
		return nil
	}
	ret := new(T)
	*ret = *v
	return ret
}

func nodesSorted(v []*tailcfg.Node) bool {
	for i, n := range v {
		if i > 0 && n.ID <= v[i-1].ID {
			return false
		}
	}
	return true
}

func sortNodes(v []*tailcfg.Node) {
	sort.Slice(v, func(i, j int) bool { return v[i].ID < v[j].ID })
}

func cloneNodes(v1 []*tailcfg.Node) []*tailcfg.Node {
	if v1 == nil {
		return nil
	}
	v2 := make([]*tailcfg.Node, len(v1))
	for i, n := range v1 {
		v2[i] = n.Clone()
	}
	return v2
}

var debugSelfIPv6Only = envknob.RegisterBool("TS_DEBUG_SELF_V6_ONLY")

func filterSelfAddresses(in []netip.Prefix) (ret []netip.Prefix) {
	switch {
	default:
		return in
	case debugSelfIPv6Only():
		for _, a := range in {
			if a.Addr().Is6() {
				ret = append(ret, a)
			}
		}
		return ret
	}
}

func copyDebugOptBools(dst, src *tailcfg.Debug) {
	copy := func(v *opt.Bool, s opt.Bool) {
		if s != "" {
			*v = s
		}
	}
	copy(&dst.DERPRoute, src.DERPRoute)
	copy(&dst.DisableSubnetsIfPAC, src.DisableSubnetsIfPAC)
	copy(&dst.DisableUPnP, src.DisableUPnP)
	copy(&dst.OneCGNATRoute, src.OneCGNATRoute)
	copy(&dst.SetForceBackgroundSTUN, src.SetForceBackgroundSTUN)
	copy(&dst.SetRandomizeClientPort, src.SetRandomizeClientPort)
	copy(&dst.TrimWGConfig, src.TrimWGConfig)
}
