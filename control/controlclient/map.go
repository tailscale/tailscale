// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"time"

	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
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

	keepAliveZ        []byte // if non-nil, the learned zstd encoding of the just-KeepAlive message for this session
	ztdDecodesForTest int    // for testing

	// sessionAliveCtx is a Background-based context that's alive for the
	// duration of the mapSession that we own the lifetime of. It's closed by
	// sessionAliveCtxClose.
	sessionAliveCtx      context.Context
	sessionAliveCtxClose context.CancelFunc // closes sessionAliveCtx

	// Optional hooks, guaranteed non-nil (set to no-op funcs) by the
	// newMapSession constructor. They must be overridden if desired
	// before the mapSession is used.

	// onDebug specifies what to do with a *tailcfg.Debug message.
	onDebug func(context.Context, *tailcfg.Debug) error

	// onSelfNodeChanged is called before the NetmapUpdater if the self node was
	// changed.
	onSelfNodeChanged func(*netmap.NetworkMap)

	// Fields storing state over the course of multiple MapResponses.
	lastPrintMap           time.Time
	lastNode               tailcfg.NodeView
	lastCapSet             set.Set[tailcfg.NodeCapability]
	peers                  map[tailcfg.NodeID]tailcfg.NodeView
	lastDNSConfig          *tailcfg.DNSConfig
	lastDERPMap            *tailcfg.DERPMap
	lastUserProfile        map[tailcfg.UserID]tailcfg.UserProfileView
	lastPacketFilterRules  views.Slice[tailcfg.FilterRule] // concatenation of all namedPacketFilters
	namedPacketFilters     map[string]views.Slice[tailcfg.FilterRule]
	lastParsedPacketFilter []filter.Match
	lastSSHPolicy          *tailcfg.SSHPolicy
	collectServices        bool
	lastDomain             string
	lastDomainAuditLogID   string
	lastHealth             []string
	lastDisplayMessages    map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
	lastPopBrowserURL      string
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
		lastUserProfile: map[tailcfg.UserID]tailcfg.UserProfileView{},

		// Non-nil no-op defaults, to be optionally overridden by the caller.
		logf:              logger.Discard,
		vlogf:             logger.Discard,
		cancel:            func() {},
		onDebug:           func(context.Context, *tailcfg.Debug) error { return nil },
		onSelfNodeChanged: func(*netmap.NetworkMap) {},
	}
	ms.sessionAliveCtx, ms.sessionAliveCtxClose = context.WithCancel(context.Background())
	return ms
}

// occasionallyPrintSummary logs summary at most once very 5 minutes. The
// summary is the Netmap.VeryConcise result from the last received map response.
func (ms *mapSession) occasionallyPrintSummary(summary string) {
	// Occasionally print the netmap header.
	// This is handy for debugging, and our logs processing
	// pipeline depends on it. (TODO: Remove this dependency.)
	now := ms.clock().Now()
	if now.Sub(ms.lastPrintMap) < 5*time.Minute {
		return
	}
	ms.lastPrintMap = now
	ms.logf("[v1] new network map (periodic):\n%s", summary)
}

func (ms *mapSession) clock() tstime.Clock {
	return cmp.Or[tstime.Clock](ms.altClock, tstime.StdClock{})
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
		if err := ms.onDebug(ctx, debug); err != nil {
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
		upgradeNode(resp.Node)
		if DevKnob.StripCaps() {
			resp.Node.Capabilities = nil
			resp.Node.CapMap = nil
		}
		// If the server is old and is still sending us Capabilities instead of
		// CapMap, convert it to CapMap early so the rest of the client code can
		// work only in terms of CapMap.
		for _, c := range resp.Node.Capabilities {
			if _, ok := resp.Node.CapMap[c]; !ok {
				mak.Set(&resp.Node.CapMap, c, nil)
			}
		}
		ms.controlKnobs.UpdateFromNodeAttributes(resp.Node.CapMap)
	}

	for _, p := range resp.Peers {
		upgradeNode(p)
	}
	for _, p := range resp.PeersChanged {
		upgradeNode(p)
	}

	// Call Node.InitDisplayNames on any changed nodes.
	initDisplayNames(cmp.Or(resp.Node.View(), ms.lastNode), resp)

	ms.patchifyPeersChanged(resp)

	ms.updateStateFromResponse(resp)

	if ms.tryHandleIncrementally(resp) {
		ms.occasionallyPrintSummary(ms.lastNetmapSummary)
		return nil
	}

	// We have to rebuild the whole netmap (lots of garbage & work downstream of
	// our UpdateFullNetmap call). This is the part we tried to avoid but
	// some field mutations (especially rare ones) aren't yet handled.

	if runtime.GOOS == "ios" {
		// Memory is tight on iOS. Free what we can while we
		// can before this potential burst of in-use memory.
		debug.FreeOSMemory()
	}

	nm := ms.netmap()
	ms.lastNetmapSummary = nm.VeryConcise()
	ms.occasionallyPrintSummary(ms.lastNetmapSummary)

	// If the self node changed, we might need to update persist.
	if resp.Node != nil {
		ms.onSelfNodeChanged(nm)
	}

	ms.netmapUpdater.UpdateFullNetmap(nm)
	return nil
}

// upgradeNode upgrades Node fields from the server into the modern forms
// not using deprecated fields.
func upgradeNode(n *tailcfg.Node) {
	if n == nil {
		return
	}
	if n.LegacyDERPString != "" {
		if n.HomeDERP == 0 {
			ip, portStr, err := net.SplitHostPort(n.LegacyDERPString)
			if ip == tailcfg.DerpMagicIP && err == nil {
				port, err := strconv.Atoi(portStr)
				if err == nil {
					n.HomeDERP = port
				}
			}
		}
		n.LegacyDERPString = ""
	}
	if DevKnob.StripHomeDERP() {
		n.HomeDERP = 0
	}

	if n.AllowedIPs == nil {
		n.AllowedIPs = slices.Clone(n.Addresses)
	}
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

		capSet := set.Set[tailcfg.NodeCapability]{}
		for _, c := range resp.Node.Capabilities {
			capSet.Add(c)
		}
		for c := range resp.Node.CapMap {
			capSet.Add(c)
		}
		ms.lastCapSet = capSet
	}

	for _, up := range resp.UserProfiles {
		ms.lastUserProfile[up.ID] = up.View()
	}
	// TODO(bradfitz): clean up old user profiles? maybe not worth it.

	if dm := resp.DERPMap; dm != nil {
		ms.vlogf("netmap: new map contains DERP map")

		// Guard against the control server accidentally sending
		// a nil region definition, which at least Headscale was
		// observed to send.
		for rid, r := range dm.Regions {
			if r == nil {
				delete(dm.Regions, rid)
			}
		}

		// In the copy/v86 wasm environment with limited networking, if the
		// control plane didn't pick our DERP home for us, do it ourselves and
		// mark all but the lowest region as NoMeasureNoHome. For prod, this
		// will be Region 1, NYC, a compromise between the US and Europe. But
		// really the control plane should pick this. This is only a fallback.
		if hostinfo.IsInVM86() {
			numCanMeasure := 0
			lowest := 0
			for rid, r := range dm.Regions {
				if !r.NoMeasureNoHome {
					numCanMeasure++
					if lowest == 0 || rid < lowest {
						lowest = rid
					}
				}
			}
			if numCanMeasure > 1 {
				for rid, r := range dm.Regions {
					if rid != lowest {
						r.NoMeasureNoHome = true
					}
				}
			}
		}

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

	var packetFilterChanged bool
	// Older way, one big blob:
	if pf := resp.PacketFilter; pf != nil {
		packetFilterChanged = true
		mak.Set(&ms.namedPacketFilters, "base", views.SliceOf(pf))
	}
	// Newer way, named chunks:
	if m := resp.PacketFilters; m != nil {
		packetFilterChanged = true
		if v, ok := m["*"]; ok && v == nil {
			ms.namedPacketFilters = nil
		}
		for k, v := range m {
			if k == "*" {
				continue
			}
			if v != nil {
				mak.Set(&ms.namedPacketFilters, k, views.SliceOf(v))
			} else {
				delete(ms.namedPacketFilters, k)
			}
		}
	}
	if packetFilterChanged {
		var concat []tailcfg.FilterRule
		for _, v := range slices.Sorted(maps.Keys(ms.namedPacketFilters)) {
			concat = ms.namedPacketFilters[v].AppendTo(concat)
		}
		ms.lastPacketFilterRules = views.SliceOf(concat)
		var err error
		ms.lastParsedPacketFilter, err = filter.MatchesFromFilterRules(concat)
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
	if resp.DisplayMessages != nil {
		if v, ok := resp.DisplayMessages["*"]; ok && v == nil {
			ms.lastDisplayMessages = nil
		}
		for k, v := range resp.DisplayMessages {
			if k == "*" {
				continue
			}
			if v != nil {
				mak.Set(&ms.lastDisplayMessages, k, *v)
			} else {
				delete(ms.lastDisplayMessages, k)
			}
		}
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
	patchCapMap       = clientmetric.NewCounter("controlclient_patch_capmap")
	patchKeySignature = clientmetric.NewCounter("controlclient_patch_keysig")

	patchifiedPeer      = clientmetric.NewCounter("controlclient_patchified_peer")
	patchifiedPeerEqual = clientmetric.NewCounter("controlclient_patchified_peer_equal")
)

// updatePeersStateFromResponseres updates ms.peers from resp.
// It takes ownership of resp.
func (ms *mapSession) updatePeersStateFromResponse(resp *tailcfg.MapResponse) (stats updateStats) {
	if ms.peers == nil {
		ms.peers = make(map[tailcfg.NodeID]tailcfg.NodeView)
	}

	if len(resp.Peers) > 0 {
		// Not delta encoded.
		stats.allNew = true
		keep := make(map[tailcfg.NodeID]bool, len(resp.Peers))
		for _, n := range resp.Peers {
			keep[n.ID] = true
			lenBefore := len(ms.peers)
			ms.peers[n.ID] = n.View()
			if len(ms.peers) == lenBefore {
				stats.changed++
			} else {
				stats.added++
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
		lenBefore := len(ms.peers)
		ms.peers[n.ID] = n.View()
		if len(ms.peers) == lenBefore {
			stats.changed++
		} else {
			stats.added++
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
			ms.peers[nodeID] = mut.View()
			stats.changed++
		}
	}

	for nodeID, online := range resp.OnlineChange {
		if vp, ok := ms.peers[nodeID]; ok {
			mut := vp.AsStruct()
			mut.Online = ptr.To(online)
			ms.peers[nodeID] = mut.View()
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
			mut.HomeDERP = pc.DERPRegion
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
		if v := pc.KeySignature; v != nil {
			mut.KeySignature = v
			patchKeySignature.Add(1)
		}
		if v := pc.CapMap; v != nil {
			mut.CapMap = v
			patchCapMap.Add(1)
		}
		ms.peers[pc.NodeID] = mut.View()
	}

	return
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
	rt := reflect.TypeFor[tailcfg.Node]()
	ret := make([]string, rt.NumField())
	for i := range rt.NumField() {
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
	return peerChangeDiff(was, n)
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
		case "Capabilities":
			// Deprecated; see https://github.com/tailscale/tailscale/issues/11508
			// And it was never sent by any known control server.
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
		case "LegacyDERPString":
			if was.LegacyDERPString() != "" || n.LegacyDERPString != "" {
				panic("unexpected; caller should've already called upgradeNode")
			}
		case "HomeDERP":
			if was.HomeDERP() != n.HomeDERP {
				pc().DERPRegion = n.HomeDERP
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
			if len(n.CapMap) != was.CapMap().Len() {
				// If they have different lengths, they're different.
				if n.CapMap == nil {
					pc().CapMap = make(tailcfg.NodeCapMap)
				} else {
					pc().CapMap = maps.Clone(n.CapMap)
				}
			} else {
				// If they have the same length, check that all their keys
				// have the same values.
				for k, v := range was.CapMap().All() {
					nv, ok := n.CapMap[k]
					if !ok || !views.SliceEqual(v, views.SliceOf(nv)) {
						pc().CapMap = maps.Clone(n.CapMap)
						break
					}
				}
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
			if wasOnline, ok := was.Online().GetOk(); ok && n.Online != nil && *n.Online != wasOnline {
				pc().Online = ptr.To(*n.Online)
			}
		case "LastSeen":
			if wasSeen, ok := was.LastSeen().GetOk(); ok && n.LastSeen != nil && !wasSeen.Equal(*n.LastSeen) {
				pc().LastSeen = ptr.To(*n.LastSeen)
			}
		case "MachineAuthorized":
			if was.MachineAuthorized() != n.MachineAuthorized {
				return nil, false
			}
		case "UnsignedPeerAPIOnly":
			if was.UnsignedPeerAPIOnly() != n.UnsignedPeerAPIOnly {
				return nil, false
			}
		case "IsWireGuardOnly":
			if was.IsWireGuardOnly() != n.IsWireGuardOnly {
				return nil, false
			}
		case "IsJailed":
			if was.IsJailed() != n.IsJailed {
				return nil, false
			}
		case "Expired":
			if was.Expired() != n.Expired {
				return nil, false
			}
		case "SelfNodeV4MasqAddrForThisPeer":
			va, vb := was.SelfNodeV4MasqAddrForThisPeer(), n.SelfNodeV4MasqAddrForThisPeer
			if !va.Valid() && vb == nil {
				continue
			}
			if va, ok := va.GetOk(); !ok || vb == nil || va != *vb {
				return nil, false
			}
		case "SelfNodeV6MasqAddrForThisPeer":
			va, vb := was.SelfNodeV6MasqAddrForThisPeer(), n.SelfNodeV6MasqAddrForThisPeer
			if !va.Valid() && vb == nil {
				continue
			}
			if va, ok := va.GetOk(); !ok || vb == nil || va != *vb {
				return nil, false
			}
		case "ExitNodeDNSResolvers":
			va, vb := was.ExitNodeDNSResolvers(), views.SliceOfViews(n.ExitNodeDNSResolvers)

			if va.Len() != vb.Len() {
				return nil, false
			}

			for i := range va.Len() {
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

func (ms *mapSession) sortedPeers() []tailcfg.NodeView {
	ret := slicesx.MapValues(ms.peers)
	slices.SortFunc(ret, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return ret
}

// netmap returns a fully populated NetworkMap from the last state seen from
// a call to updateStateFromResponse, filling in omitted
// information from prior MapResponse values.
func (ms *mapSession) netmap() *netmap.NetworkMap {
	peerViews := ms.sortedPeers()

	var msgs map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
	if len(ms.lastDisplayMessages) != 0 {
		msgs = ms.lastDisplayMessages
	} else if len(ms.lastHealth) > 0 {
		// Convert all ms.lastHealth to the new [netmap.NetworkMap.DisplayMessages]
		for _, h := range ms.lastHealth {
			id := "health-" + strhash(h) // Unique ID in case there is more than one health message
			mak.Set(&msgs, tailcfg.DisplayMessageID(id), tailcfg.DisplayMessage{
				Title:    "Coordination server reports an issue",
				Severity: tailcfg.SeverityMedium,
				Text:     "The coordination server is reporting a health issue: " + h,
			})
		}
	}

	nm := &netmap.NetworkMap{
		NodeKey:           ms.publicNodeKey,
		MachineKey:        ms.machinePubKey,
		Peers:             peerViews,
		UserProfiles:      make(map[tailcfg.UserID]tailcfg.UserProfileView),
		Domain:            ms.lastDomain,
		DomainAuditLogID:  ms.lastDomainAuditLogID,
		DNS:               *ms.lastDNSConfig,
		PacketFilter:      ms.lastParsedPacketFilter,
		PacketFilterRules: ms.lastPacketFilterRules,
		SSHPolicy:         ms.lastSSHPolicy,
		CollectServices:   ms.collectServices,
		DERPMap:           ms.lastDERPMap,
		DisplayMessages:   msgs,
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
		nm.AllCaps = ms.lastCapSet
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

func strhash(h string) string {
	s := sha256.New()
	io.WriteString(s, h)
	return hex.EncodeToString(s.Sum(nil))
}
