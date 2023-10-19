// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/cmpx"
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
	netmapUpdater  NetmapUpdater       // called on changes (in addition to the optional hooks below)
	controlKnobs   *controlknobs.Knobs // or nil
	privateNodeKey key.NodePrivate
	publicNodeKey  key.NodePublic
	logf           logger.Logf
	vlogf          logger.Logf
	machinePubKey  key.MachinePublic
	altClock       tstime.Clock       // if nil, regular time is used
	cancel         context.CancelFunc // always non-nil, shuts down caller's base long poll context
	watchdogReset  chan struct{}      // send to request that the long poll activity watchdog timeout be reset

	// sessionAliveCtx is a Background-based context that's alive for the
	// duration of the mapSession that we own the lifetime of. It's closed by
	// sessionAliveCtxClose.
	sessionAliveCtx      context.Context
	sessionAliveCtxClose context.CancelFunc // closes sessionAliveCtx

	// Optional hooks, set once before use.

	// onDebug specifies what to do with a *tailcfg.Debug message.
	// If the watchdogReset chan is nil, it's not used. Otherwise it can be sent to
	// to request that the long poll activity watchdog timeout be reset.
	onDebug func(_ context.Context, _ *tailcfg.Debug, watchdogReset chan<- struct{}) error

	// onConciseNetMapSummary, if non-nil, is called with the Netmap.VeryConcise summary
	// whenever a map response is received.
	onConciseNetMapSummary func(string)

	// onSelfNodeChanged is called before the NetmapUpdater if the self node was
	// changed.
	onSelfNodeChanged func(*netmap.NetworkMap)

	// Fields storing state over the course of multiple MapResponses.
	lastNode               tailcfg.NodeView
	peers                  map[tailcfg.NodeID]*tailcfg.NodeView // pointer to view (oddly). same pointers as sortedPeers.
	sortedPeers            []*tailcfg.NodeView                  // same pointers as peers, but sorted by Node.ID
	lastDNSConfig          *tailcfg.DNSConfig
	lastDERPMap            *tailcfg.DERPMap
	lastUserProfile        map[tailcfg.UserID]tailcfg.UserProfile
	lastPacketFilterRules  views.Slice[tailcfg.FilterRule]
	lastParsedPacketFilter []filter.Match
	lastSSHPolicy          *tailcfg.SSHPolicy
	collectServices        bool
	lastDomain             string
	lastDomainAuditLogID   string
	lastHealth             []string
	lastPopBrowserURL      string
	stickyDebug            tailcfg.Debug // accumulated opt.Bool values
	lastTKAInfo            *tailcfg.TKAInfo
	lastNetmapSummary      string // from NetworkMap.VeryConcise
}

// newMapSession returns a mostly unconfigured new mapSession.
//
// Modify its optional fields on the returned value before use.
//
// It must have its Close method called to release resources.
func newMapSession(privateNodeKey key.NodePrivate, nu NetmapUpdater, controlKnobs *controlknobs.Knobs) *mapSession {
	ms := &mapSession{
		netmapUpdater:   nu,
		controlKnobs:    controlKnobs,
		privateNodeKey:  privateNodeKey,
		publicNodeKey:   privateNodeKey.Public(),
		lastDNSConfig:   new(tailcfg.DNSConfig),
		lastUserProfile: map[tailcfg.UserID]tailcfg.UserProfile{},
		watchdogReset:   make(chan struct{}),

		// Non-nil no-op defaults, to be optionally overridden by the caller.
		logf:                   logger.Discard,
		vlogf:                  logger.Discard,
		cancel:                 func() {},
		onDebug:                func(context.Context, *tailcfg.Debug, chan<- struct{}) error { return nil },
		onConciseNetMapSummary: func(string) {},
		onSelfNodeChanged:      func(*netmap.NetworkMap) {},
	}
	ms.sessionAliveCtx, ms.sessionAliveCtxClose = context.WithCancel(context.Background())
	return ms
}

func (ms *mapSession) clock() tstime.Clock {
	return cmpx.Or[tstime.Clock](ms.altClock, tstime.StdClock{})
}

// StartWatchdog starts the session's watchdog timer.
// If there's no activity in too long, it tears down the connection.
// Call Close to release these resources.
func (ms *mapSession) StartWatchdog() {
	timer, timedOutChan := ms.clock().NewTimer(watchdogTimeout)
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-ms.sessionAliveCtx.Done():
				ms.vlogf("netmap: ending timeout goroutine")
				return
			case <-timedOutChan:
				ms.logf("map response long-poll timed out!")
				ms.cancel()
				return
			case <-ms.watchdogReset:
				if !timer.Stop() {
					select {
					case <-timedOutChan:
					case <-ms.sessionAliveCtx.Done():
						ms.vlogf("netmap: ending timeout goroutine")
						return
					}
				}
				ms.vlogf("netmap: reset timeout timer")
				timer.Reset(watchdogTimeout)
			}
		}
	}()
}

func (ms *mapSession) Close() {
	ms.sessionAliveCtxClose()
}

// HandleNonKeepAliveMapResponse handles a non-KeepAlive MapResponse (full or
// incremental).
//
// All fields that are valid on a KeepAlive MapResponse have already been
// handled.
//
// TODO(bradfitz): make this handle all fields later. For now (2023-08-20) this
// is [re]factoring progress enough.
func (ms *mapSession) HandleNonKeepAliveMapResponse(ctx context.Context, resp *tailcfg.MapResponse) error {
	if debug := resp.Debug; debug != nil {
		if err := ms.onDebug(ctx, debug, ms.watchdogReset); err != nil {
			return err
		}
	}

	if DevKnob.StripEndpoints() {
		for _, p := range resp.Peers {
			p.Endpoints = nil
		}
		for _, p := range resp.PeersChanged {
			p.Endpoints = nil
		}
	}

	// For responses that mutate the self node, check for updated nodeAttrs.
	if resp.Node != nil {
		if DevKnob.StripCaps() {
			resp.Node.Capabilities = nil
			resp.Node.CapMap = nil
		}
		ms.controlKnobs.UpdateFromNodeAttributes(resp.Node.Capabilities, resp.Node.CapMap)
	}

	// Call Node.InitDisplayNames on any changed nodes.
	initDisplayNames(cmpx.Or(resp.Node.View(), ms.lastNode), resp)

	ms.patchifyPeersChanged(resp)

	ms.updateStateFromResponse(resp)

	if ms.tryHandleIncrementally(resp) {
		ms.onConciseNetMapSummary(ms.lastNetmapSummary) // every 5s log
		return nil
	}

	// We have to rebuild the whole netmap (lots of garbage & work downstream of
	// our UpdateFullNetmap call). This is the part we tried to avoid but
	// some field mutations (especially rare ones) aren't yet handled.

	nm := ms.netmap()
	ms.lastNetmapSummary = nm.VeryConcise()
	ms.onConciseNetMapSummary(ms.lastNetmapSummary)

	// If the self node changed, we might need to update persist.
	if resp.Node != nil {
		ms.onSelfNodeChanged(nm)
	}

	ms.netmapUpdater.UpdateFullNetmap(nm)
	return nil
}

func (ms *mapSession) tryHandleIncrementally(res *tailcfg.MapResponse) bool {
	if ms.controlKnobs != nil && ms.controlKnobs.DisableDeltaUpdates.Load() {
		return false
	}
	nud, ok := ms.netmapUpdater.(NetmapDeltaUpdater)
	if !ok {
		return false
	}
	mutations, ok := netmap.MutationsFromMapResponse(res, time.Now())
	if ok && len(mutations) > 0 {
		return nud.UpdateNetmapDelta(mutations)
	}
	return ok
}

// updateStats are some stats from updateStateFromResponse, primarily for
// testing. It's meant to be cheap enough to always compute, though. It doesn't
// allocate.
type updateStats struct {
	allNew  bool
	added   int
	removed int
	changed int
}

// updateStateFromResponse updates ms from res. It takes ownership of res.
func (ms *mapSession) updateStateFromResponse(resp *tailcfg.MapResponse) {
	ms.updatePeersStateFromResponse(resp)

	if resp.Node != nil {
		ms.lastNode = resp.Node.View()
	}

	for _, up := range resp.UserProfiles {
		ms.lastUserProfile[up.ID] = up
	}
	// TODO(bradfitz): clean up old user profiles? maybe not worth it.

	if dm := resp.DERPMap; dm != nil {
		ms.vlogf("netmap: new map contains DERP map")

		// Zero-valued fields in a DERPMap mean that we're not changing
		// anything and are using the previous value(s).
		if ldm := ms.lastDERPMap; ldm != nil {
			if dm.Regions == nil {
				dm.Regions = ldm.Regions
				dm.OmitDefaultRegions = ldm.OmitDefaultRegions
			}
			if dm.HomeParams == nil {
				dm.HomeParams = ldm.HomeParams
			} else if oldhh := ldm.HomeParams; oldhh != nil {
				// Propagate sub-fields of HomeParams
				hh := dm.HomeParams
				if hh.RegionScore == nil {
					hh.RegionScore = oldhh.RegionScore
				}
			}
		}

		ms.lastDERPMap = dm
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
}

var (
	patchDERPRegion   = clientmetric.NewCounter("controlclient_patch_derp")
	patchEndpoints    = clientmetric.NewCounter("controlclient_patch_endpoints")
	patchCap          = clientmetric.NewCounter("controlclient_patch_capver")
	patchKey          = clientmetric.NewCounter("controlclient_patch_key")
	patchDiscoKey     = clientmetric.NewCounter("controlclient_patch_discokey")
	patchOnline       = clientmetric.NewCounter("controlclient_patch_online")
	patchLastSeen     = clientmetric.NewCounter("controlclient_patch_lastseen")
	patchKeyExpiry    = clientmetric.NewCounter("controlclient_patch_keyexpiry")
	patchCapabilities = clientmetric.NewCounter("controlclient_patch_capabilities")
	patchCapMap       = clientmetric.NewCounter("controlclient_patch_capmap")
	patchKeySignature = clientmetric.NewCounter("controlclient_patch_keysig")

	patchifiedPeer      = clientmetric.NewCounter("controlclient_patchified_peer")
	patchifiedPeerEqual = clientmetric.NewCounter("controlclient_patchified_peer_equal")
)

// updatePeersStateFromResponseres updates ms.peers and ms.sortedPeers from res. It takes ownership of res.
func (ms *mapSession) updatePeersStateFromResponse(resp *tailcfg.MapResponse) (stats updateStats) {
	defer func() {
		if stats.removed > 0 || stats.added > 0 {
			ms.rebuildSorted()
		}
	}()

	if ms.peers == nil {
		ms.peers = make(map[tailcfg.NodeID]*tailcfg.NodeView)
	}

	if len(resp.Peers) > 0 {
		// Not delta encoded.
		stats.allNew = true
		keep := make(map[tailcfg.NodeID]bool, len(resp.Peers))
		for _, n := range resp.Peers {
			keep[n.ID] = true
			if vp, ok := ms.peers[n.ID]; ok {
				stats.changed++
				*vp = n.View()
			} else {
				stats.added++
				ms.peers[n.ID] = ptr.To(n.View())
			}
		}
		for id := range ms.peers {
			if !keep[id] {
				stats.removed++
				delete(ms.peers, id)
			}
		}
		// Peers precludes all other delta operations so just return.
		return
	}

	for _, id := range resp.PeersRemoved {
		if _, ok := ms.peers[id]; ok {
			delete(ms.peers, id)
			stats.removed++
		}
	}

	for _, n := range resp.PeersChanged {
		if vp, ok := ms.peers[n.ID]; ok {
			stats.changed++
			*vp = n.View()
		} else {
			stats.added++
			ms.peers[n.ID] = ptr.To(n.View())
		}
	}

	for nodeID, seen := range resp.PeerSeenChange {
		if vp, ok := ms.peers[nodeID]; ok {
			mut := vp.AsStruct()
			if seen {
				mut.LastSeen = ptr.To(clock.Now())
			} else {
				mut.LastSeen = nil
			}
			*vp = mut.View()
			stats.changed++
		}
	}

	for nodeID, online := range resp.OnlineChange {
		if vp, ok := ms.peers[nodeID]; ok {
			mut := vp.AsStruct()
			mut.Online = ptr.To(online)
			*vp = mut.View()
			stats.changed++
		}
	}

	for _, pc := range resp.PeersChangedPatch {
		vp, ok := ms.peers[pc.NodeID]
		if !ok {
			continue
		}
		stats.changed++
		mut := vp.AsStruct()
		if pc.DERPRegion != 0 {
			mut.DERP = fmt.Sprintf("%s:%v", tailcfg.DerpMagicIP, pc.DERPRegion)
			patchDERPRegion.Add(1)
		}
		if pc.Cap != 0 {
			mut.Cap = pc.Cap
			patchCap.Add(1)
		}
		if pc.Endpoints != nil {
			mut.Endpoints = pc.Endpoints
			patchEndpoints.Add(1)
		}
		if pc.Key != nil {
			mut.Key = *pc.Key
			patchKey.Add(1)
		}
		if pc.DiscoKey != nil {
			mut.DiscoKey = *pc.DiscoKey
			patchDiscoKey.Add(1)
		}
		if v := pc.Online; v != nil {
			mut.Online = ptr.To(*v)
			patchOnline.Add(1)
		}
		if v := pc.LastSeen; v != nil {
			mut.LastSeen = ptr.To(*v)
			patchLastSeen.Add(1)
		}
		if v := pc.KeyExpiry; v != nil {
			mut.KeyExpiry = *v
			patchKeyExpiry.Add(1)
		}
		if v := pc.Capabilities; v != nil {
			mut.Capabilities = *v
			patchCapabilities.Add(1)
		}
		if v := pc.KeySignature; v != nil {
			mut.KeySignature = v
			patchKeySignature.Add(1)
		}
		if v := pc.CapMap; v != nil {
			mut.CapMap = v
			patchCapMap.Add(1)
		}
		*vp = mut.View()
	}

	return
}

// rebuildSorted rebuilds ms.sortedPeers from ms.peers. It should be called
// after any additions or removals from peers.
func (ms *mapSession) rebuildSorted() {
	if ms.sortedPeers == nil {
		ms.sortedPeers = make([]*tailcfg.NodeView, 0, len(ms.peers))
	} else {
		if len(ms.sortedPeers) > len(ms.peers) {
			clear(ms.sortedPeers[len(ms.peers):])
		}
		ms.sortedPeers = ms.sortedPeers[:0]
	}
	for _, p := range ms.peers {
		ms.sortedPeers = append(ms.sortedPeers, p)
	}
	sort.Slice(ms.sortedPeers, func(i, j int) bool {
		return ms.sortedPeers[i].ID() < ms.sortedPeers[j].ID()
	})
}

func (ms *mapSession) addUserProfile(nm *netmap.NetworkMap, userID tailcfg.UserID) {
	if userID == 0 {
		return
	}
	if _, dup := nm.UserProfiles[userID]; dup {
		// Already populated it from a previous peer.
		return
	}
	if up, ok := ms.lastUserProfile[userID]; ok {
		nm.UserProfiles[userID] = up
	}
}

var debugPatchifyPeer = envknob.RegisterBool("TS_DEBUG_PATCHIFY_PEER")

// patchifyPeersChanged mutates resp to promote PeersChanged entries to PeersChangedPatch
// when possible.
func (ms *mapSession) patchifyPeersChanged(resp *tailcfg.MapResponse) {
	filtered := resp.PeersChanged[:0]
	for _, n := range resp.PeersChanged {
		if p, ok := ms.patchifyPeer(n); ok {
			patchifiedPeer.Add(1)
			if debugPatchifyPeer() {
				patchj, _ := json.Marshal(p)
				ms.logf("debug: patchifyPeer[ID=%v]: %s", n.ID, patchj)
			}
			if p != nil {
				resp.PeersChangedPatch = append(resp.PeersChangedPatch, p)
			} else {
				patchifiedPeerEqual.Add(1)
			}
		} else {
			filtered = append(filtered, n)
		}
	}
	resp.PeersChanged = filtered
	if len(resp.PeersChanged) == 0 {
		resp.PeersChanged = nil
	}
}

var nodeFields = sync.OnceValue(getNodeFields)

// getNodeFields returns the fails of tailcfg.Node.
func getNodeFields() []string {
	rt := reflect.TypeOf((*tailcfg.Node)(nil)).Elem()
	ret := make([]string, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		ret[i] = rt.Field(i).Name
	}
	return ret
}

// patchifyPeer returns a *tailcfg.PeerChange of the session's existing copy of
// the n.ID Node to n.
//
// It returns ok=false if a patch can't be made, (V, ok) on a delta, or (nil,
// true) if all the fields were identical (a zero change).
func (ms *mapSession) patchifyPeer(n *tailcfg.Node) (_ *tailcfg.PeerChange, ok bool) {
	was, ok := ms.peers[n.ID]
	if !ok {
		return nil, false
	}
	return peerChangeDiff(*was, n)
}

// peerChangeDiff returns the difference from 'was' to 'n', if possible.
//
// It returns (nil, true) if the fields were identical.
func peerChangeDiff(was tailcfg.NodeView, n *tailcfg.Node) (_ *tailcfg.PeerChange, ok bool) {
	var ret *tailcfg.PeerChange
	pc := func() *tailcfg.PeerChange {
		if ret == nil {
			ret = new(tailcfg.PeerChange)
		}
		return ret
	}
	for _, field := range nodeFields() {
		switch field {
		default:
			// The whole point of using reflect in this function is to panic
			// here in tests if we forget to handle a new field.
			panic("unhandled field: " + field)
		case "computedHostIfDifferent", "ComputedName", "ComputedNameWithHost":
			// Caller's responsibility to have populated these.
			continue
		case "DataPlaneAuditLogID":
			//  Not sent for peers.
		case "ID":
			if was.ID() != n.ID {
				return nil, false
			}
		case "StableID":
			if was.StableID() != n.StableID {
				return nil, false
			}
		case "Name":
			if was.Name() != n.Name {
				return nil, false
			}
		case "User":
			if was.User() != n.User {
				return nil, false
			}
		case "Sharer":
			if was.Sharer() != n.Sharer {
				return nil, false
			}
		case "Key":
			if was.Key() != n.Key {
				pc().Key = ptr.To(n.Key)
			}
		case "KeyExpiry":
			if !was.KeyExpiry().Equal(n.KeyExpiry) {
				pc().KeyExpiry = ptr.To(n.KeyExpiry)
			}
		case "KeySignature":
			if !was.KeySignature().Equal(n.KeySignature) {
				pc().KeySignature = slices.Clone(n.KeySignature)
			}
		case "Machine":
			if was.Machine() != n.Machine {
				return nil, false
			}
		case "DiscoKey":
			if was.DiscoKey() != n.DiscoKey {
				pc().DiscoKey = ptr.To(n.DiscoKey)
			}
		case "Addresses":
			if !views.SliceEqual(was.Addresses(), views.SliceOf(n.Addresses)) {
				return nil, false
			}
		case "AllowedIPs":
			if !views.SliceEqual(was.AllowedIPs(), views.SliceOf(n.AllowedIPs)) {
				return nil, false
			}
		case "Endpoints":
			if !views.SliceEqual(was.Endpoints(), views.SliceOf(n.Endpoints)) {
				pc().Endpoints = slices.Clone(n.Endpoints)
			}
		case "DERP":
			if was.DERP() != n.DERP {
				ip, portStr, err := net.SplitHostPort(n.DERP)
				if err != nil || ip != "127.3.3.40" {
					return nil, false
				}
				port, err := strconv.Atoi(portStr)
				if err != nil || port < 1 || port > 65535 {
					return nil, false
				}
				pc().DERPRegion = port
			}
		case "Hostinfo":
			if !was.Hostinfo().Valid() && !n.Hostinfo.Valid() {
				continue
			}
			if !was.Hostinfo().Valid() || !n.Hostinfo.Valid() {
				return nil, false
			}
			if !was.Hostinfo().Equal(n.Hostinfo) {
				return nil, false
			}
		case "Created":
			if !was.Created().Equal(n.Created) {
				return nil, false
			}
		case "Cap":
			if was.Cap() != n.Cap {
				pc().Cap = n.Cap
			}
		case "CapMap":
			if n.CapMap != nil {
				pc().CapMap = n.CapMap
			}
		case "Tags":
			if !views.SliceEqual(was.Tags(), views.SliceOf(n.Tags)) {
				return nil, false
			}
		case "PrimaryRoutes":
			if !views.SliceEqual(was.PrimaryRoutes(), views.SliceOf(n.PrimaryRoutes)) {
				return nil, false
			}
		case "Online":
			wasOnline := was.Online()
			if n.Online != nil && wasOnline != nil && *n.Online != *wasOnline {
				pc().Online = ptr.To(*n.Online)
			}
		case "LastSeen":
			wasSeen := was.LastSeen()
			if n.LastSeen != nil && wasSeen != nil && !wasSeen.Equal(*n.LastSeen) {
				pc().LastSeen = ptr.To(*n.LastSeen)
			}
		case "MachineAuthorized":
			if was.MachineAuthorized() != n.MachineAuthorized {
				return nil, false
			}
		case "Capabilities":
			if !views.SliceEqual(was.Capabilities(), views.SliceOf(n.Capabilities)) {
				pc().Capabilities = ptr.To(n.Capabilities)
			}
		case "UnsignedPeerAPIOnly":
			if was.UnsignedPeerAPIOnly() != n.UnsignedPeerAPIOnly {
				return nil, false
			}
		case "IsWireGuardOnly":
			if was.IsWireGuardOnly() != n.IsWireGuardOnly {
				return nil, false
			}
		case "Expired":
			if was.Expired() != n.Expired {
				return nil, false
			}
		case "SelfNodeV4MasqAddrForThisPeer":
			va, vb := was.SelfNodeV4MasqAddrForThisPeer(), n.SelfNodeV4MasqAddrForThisPeer
			if va == nil && vb == nil {
				continue
			}
			if va == nil || vb == nil || *va != *vb {
				return nil, false
			}
		case "SelfNodeV6MasqAddrForThisPeer":
			va, vb := was.SelfNodeV6MasqAddrForThisPeer(), n.SelfNodeV6MasqAddrForThisPeer
			if va == nil && vb == nil {
				continue
			}
			if va == nil || vb == nil || *va != *vb {
				return nil, false
			}
		case "ExitNodeDNSResolvers":
			va, vb := was.ExitNodeDNSResolvers(), views.SliceOfViews(n.ExitNodeDNSResolvers)

			if va.Len() != vb.Len() {
				return nil, false
			}

			for i := range va.LenIter() {
				if !va.At(i).Equal(vb.At(i)) {
					return nil, false
				}
			}

		}
	}
	if ret != nil {
		ret.NodeID = n.ID
	}
	return ret, true
}

// netmap returns a fully populated NetworkMap from the last state seen from
// a call to updateStateFromResponse, filling in omitted
// information from prior MapResponse values.
func (ms *mapSession) netmap() *netmap.NetworkMap {
	peerViews := make([]tailcfg.NodeView, len(ms.sortedPeers))
	for i, vp := range ms.sortedPeers {
		peerViews[i] = *vp
	}

	nm := &netmap.NetworkMap{
		NodeKey:           ms.publicNodeKey,
		PrivateKey:        ms.privateNodeKey,
		MachineKey:        ms.machinePubKey,
		Peers:             peerViews,
		UserProfiles:      make(map[tailcfg.UserID]tailcfg.UserProfile),
		Domain:            ms.lastDomain,
		DomainAuditLogID:  ms.lastDomainAuditLogID,
		DNS:               *ms.lastDNSConfig,
		PacketFilter:      ms.lastParsedPacketFilter,
		PacketFilterRules: ms.lastPacketFilterRules,
		SSHPolicy:         ms.lastSSHPolicy,
		CollectServices:   ms.collectServices,
		DERPMap:           ms.lastDERPMap,
		ControlHealth:     ms.lastHealth,
		TKAEnabled:        ms.lastTKAInfo != nil && !ms.lastTKAInfo.Disabled,
	}

	if ms.lastTKAInfo != nil && ms.lastTKAInfo.Head != "" {
		if err := nm.TKAHead.UnmarshalText([]byte(ms.lastTKAInfo.Head)); err != nil {
			ms.logf("error unmarshalling TKAHead: %v", err)
			nm.TKAEnabled = false
		}
	}

	if node := ms.lastNode; node.Valid() {
		nm.SelfNode = node
		nm.Expiry = node.KeyExpiry()
		nm.Name = node.Name()
	}

	ms.addUserProfile(nm, nm.User())
	for _, peer := range peerViews {
		ms.addUserProfile(nm, peer.Sharer())
		ms.addUserProfile(nm, peer.User())
	}
	if DevKnob.ForceProxyDNS() {
		nm.DNS.Proxied = true
	}
	return nm
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
