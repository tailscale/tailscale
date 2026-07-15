// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"context"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"go4.org/netipx"
	"tailscale.com/appc"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/net/routecheck/peernode"
	"tailscale.com/net/routemanager"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/mapx"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/testenv"
	"tailscale.com/wgengine/filter"
)

// nodeBackend is node-specific [LocalBackend] state. It is usually the current node.
//
// Its exported methods are safe for concurrent use, but the struct is not a snapshot of state at a given moment;
// its state can change between calls. For example, asking for the same value (e.g., netmap or prefs) twice
// may return different results. Returned values are immutable and safe for concurrent use.
//
// If both the [LocalBackend]'s internal mutex and the [nodeBackend] mutex must be held at the same time,
// the [LocalBackend] mutex must be acquired first. See the comment on the [LocalBackend] field for more details.
//
// Two pointers to different [nodeBackend] instances represent different local nodes.
// However, there's currently a bug where a new [nodeBackend] might not be created
// during an implicit node switch (see tailscale/corp#28014).
//
// In the future, we might want to include at least the following in this struct (in addition to the current fields).
// However, not everything should be exported or otherwise made available to the outside world (e.g. [ipnext] extensions,
// peer API handlers, etc.).
//   - [ipn.State]: when the LocalBackend switches to a different [nodeBackend], it can update the state of the old one.
//   - [ipn.LoginProfileView] and [ipn.Prefs]: we should update them when the [profileManager] reports changes to them.
//     In the future, [profileManager] (and the corresponding methods of the [LocalBackend]) can be made optional,
//     and something else could be used to set them once or update them as needed.
//   - [tailcfg.HostinfoView]: it includes certain fields that are tied to the current profile/node/prefs. We should also
//     update to build it once instead of mutating it in twelvety different places.
//   - [filter.Filter] (normal and jailed, along with the filterHash): the nodeBackend could have a method to (re-)build
//     the filter for the current netmap/prefs (see [LocalBackend.updateFilterLocked]), and it needs to track the current
//     filters and their hash.
//   - Fields related to a requested or required (re-)auth: authURL, authURLTime, authActor, keyExpired, etc.
//   - [controlclient.Client]/[*controlclient.Auto]: the current control client. It is ties to a node identity.
//   - [tkaState]: it is tied to the current profile / node.
//   - Fields related to scheduled node expiration: nmExpiryTimer, numClientStatusCalls, [expiryManager].
//
// It should not include any fields used by specific features that don't belong in [LocalBackend].
// Even if they're tied to the local node, instead of moving them here, we should extract the entire feature
// into a separate package and have it install proper hooks.
type nodeBackend struct {
	logf logger.Logf

	ctx       context.Context         // canceled by [nodeBackend.shutdown]
	ctxCancel context.CancelCauseFunc // cancels ctx

	// filterAtomic is a stateful packet filter. Immutable once created, but can be
	// replaced with a new one.
	filterAtomic atomic.Pointer[filter.Filter]

	// initialized once and immutable
	eventClient    *eventbus.Client
	derpMapViewPub *eventbus.Publisher[tailcfg.DERPMapView]

	// homeDERP lives here temporarily. as long as mapSession is short lived, we
	// don't have a location delivering netmaps to local backend that knows our
	// homeDERP hence why it is cached here for now.
	// TODO(cmol): move this field into a refactored mapSession that is not
	// short lived.
	homeDERP atomic.Int64

	// TODO(nickkhyl): maybe use sync.RWMutex?
	mu syncs.Mutex // protects the following fields

	shutdownOnce sync.Once     // guards calling [nodeBackend.shutdown]
	readyCh      chan struct{} // closed by [nodeBackend.ready]; nil after shutdown

	// NetMap is the most recently set full netmap from the controlclient.
	// It can't be mutated in place once set. Because it can't be mutated in place,
	// delta updates from the control server don't apply to it. Instead, use
	// the peers map to get up-to-date information on the state of peers.
	// In general, avoid using the netMap.Peers slice. We'd like it to go away
	// as of 2023-09-17.
	// TODO(nickkhyl): make it an atomic pointer to avoid the need for a mutex?
	netMap *netmap.NetworkMap

	// peers is the set of current peers and their current values after applying
	// delta node mutations as they come in (with mu held). The map values can be
	// given out to callers, but the map itself can be mutated in place (with mu held)
	// and must not escape the [nodeBackend].
	peers map[tailcfg.NodeID]tailcfg.NodeView

	// nodeByAddr maps nodes' own addresses (excluding subnet routes) to node IDs.
	// It is mutated in place (with mu held) and must not escape the [nodeBackend].
	nodeByAddr map[netip.Addr]tailcfg.NodeID

	// nodeByKey is an index of node public key to node ID for fast lookups.
	// It is mutated in place (with mu held) and must not escape the [nodeBackend].
	nodeByKey map[key.NodePublic]tailcfg.NodeID

	// nodeByWGString indexes wireguard-go's truncated peer-string form
	// (see [key.NodePublic.WireGuardGoString]) to node ID. It mirrors
	// nodeByKey and lets the wireguard-go log path resolve
	// "peer(XXXX…YYYY)" references in O(1), without scanning every
	// peer, while still tolerating the fact that the wireguard-go form
	// is lossy and can't be inverted to a [key.NodePublic].
	// It is mutated in place (with mu held) and must not escape the [nodeBackend].
	nodeByWGString map[string]tailcfg.NodeID

	// nodeByStableID is an index of peer stable node ID to node ID.
	// Unlike nodeByAddr and nodeByKey, it covers only peers, not the
	// self node.
	// It is mutated in place (with mu held) and must not escape the [nodeBackend].
	nodeByStableID map[tailcfg.StableNodeID]tailcfg.NodeID

	// nodeByName maps MagicDNS hostnames (lowercase, no trailing dot) to
	// node IDs. Both the FQDN and the short name (suffix stripped) are
	// keys. It is used by the tsdial MagicDNS resolution callback.
	// It is mutated in place (with mu held) and must not escape the [nodeBackend].
	nodeByName map[string]tailcfg.NodeID

	// extraDNS stores DNS.ExtraRecords A/AAAA entries from the netmap
	// (typically service VIPs pushed by control), keyed by canonicalized
	// hostname (lowercase, no trailing dot).
	extraDNS map[string]netip.Addr

	// userProfiles is the live set of user profiles, updated incrementally
	// by mergeUserProfiles as deltas arrive. It parallels the peers map:
	// netMap.UserProfiles is the frozen snapshot from the last full install,
	// while this field reflects incremental updates. Readers that need a
	// snapshot (e.g. the legacy Notify.NetMap path) must clone this map.
	userProfiles map[tailcfg.UserID]tailcfg.UserProfileView

	// packetFilterRules and packetFilter are the live packet filter state,
	// updated by setPacketFilter as deltas arrive. Like userProfiles, they
	// exist separately from netMap's frozen fields so that concurrent
	// JSON-encoding of a Notify.NetMap snapshot doesn't race with writes.
	packetFilterRules views.Slice[tailcfg.FilterRule]
	packetFilter      []filter.Match

	// keyWaitersForTest is the test-only registry of channels waiting for
	// a given peer key to first appear in the netmap. See
	// [nodeBackend.AwaitNodeKeyForTest]. It is populated lazily and remains
	// nil in production, where no test installs a waiter.
	keyWaitersForTest map[key.NodePublic]chan struct{}

	// tsmpLearnedDisco records, per node key, a peer disco key that was
	// learned via TSMP (that is, over an existing WireGuard session with
	// that peer). When a netmap update later reports the same disco key
	// change, the peer's WireGuard session does not need to be reset,
	// because the change demonstrably arrived over a working session.
	// See [nodeBackend.discoChangedLocked].
	tsmpLearnedDisco map[key.NodePublic]key.DiscoPublic

	// routeMgr tracks this node's view of which IPs route to which
	// peers and publishes lock-free snapshots for the data plane and
	// the OS router. It is initialized once and immutable, but its
	// Begin/Commit mutations must be serialized, which we do by only
	// mutating it with mu held.
	routeMgr *routemanager.RouteManager
}

func newNodeBackend(ctx context.Context, logf logger.Logf, bus *eventbus.Bus) *nodeBackend {
	ctx, ctxCancel := context.WithCancelCause(ctx)
	nb := &nodeBackend{
		logf:        logf,
		ctx:         ctx,
		ctxCancel:   ctxCancel,
		eventClient: bus.Client("ipnlocal.nodeBackend"),
		readyCh:     make(chan struct{}),
		routeMgr:    routemanager.New(logf),
	}
	// Default filter blocks everything and logs nothing.
	noneFilter := filter.NewAllowNone(logger.Discard, &netipx.IPSet{})
	nb.filterAtomic.Store(noneFilter)
	nb.derpMapViewPub = eventbus.Publish[tailcfg.DERPMapView](nb.eventClient)
	return nb
}

// Context returns a context that is canceled when the [nodeBackend] shuts down,
// either because [LocalBackend] is switching to a different [nodeBackend]
// or is shutting down itself.
func (nb *nodeBackend) Context() context.Context {
	return nb.ctx
}

// Self returns the current node.
func (nb *nodeBackend) Self() tailcfg.NodeView {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return tailcfg.NodeView{}
	}
	return nb.netMap.SelfNode
}

func (nb *nodeBackend) SelfUserID() tailcfg.UserID {
	self := nb.Self()
	if !self.Valid() {
		return 0
	}
	return self.User()
}

// SelfHasCap reports whether the specified capability was granted to the self node in the most recent netmap.
func (nb *nodeBackend) SelfHasCap(wantCap tailcfg.NodeCapability) bool {
	return nb.SelfHasCapOr(wantCap, false)
}

// SelfHasCapOr is like [nodeBackend.SelfHasCap], but returns the specified default value
// if the netmap is not available yet.
func (nb *nodeBackend) SelfHasCapOr(wantCap tailcfg.NodeCapability, def bool) bool {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return def
	}
	return nb.netMap.AllCaps.Contains(wantCap)
}

func (nb *nodeBackend) NetworkProfile() ipn.NetworkProfile {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return ipn.NetworkProfile{
		// These are ok to call with nil netMap.
		MagicDNSName: nb.netMap.MagicDNSSuffix(),
		DomainName:   nb.netMap.DomainName(),
		DisplayName:  nb.netMap.TailnetDisplayName(),
	}
}

// TODO(nickkhyl): update it to return a [tailcfg.DERPMapView]?
func (nb *nodeBackend) DERPMap() *tailcfg.DERPMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return nil
	}
	return nb.netMap.DERPMap
}

func (nb *nodeBackend) NodeByAddr(ip netip.Addr) (_ tailcfg.NodeID, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nid, ok := nb.nodeByAddr[ip]
	return nid, ok
}

func (nb *nodeBackend) NodeByKey(k key.NodePublic) (_ tailcfg.NodeID, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nid, ok := nb.nodeByKey[k]
	return nid, ok
}

// PeerAllowedIPs returns the prefixes from which the peer with the
// given public key is currently allowed to originate traffic, or
// ok=false if the key is unknown or the peer currently contributes no
// prefixes.
func (nb *nodeBackend) PeerAllowedIPs(k key.NodePublic) ([]netip.Prefix, bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	id, ok := nb.nodeByKey[k]
	if !ok {
		return nil, false
	}
	// Holding nb.mu satisfies routeMgr's serialization requirement:
	// all routeMgr mutations also run under nb.mu.
	return nb.routeMgr.PeerAllowedIPs(id)
}

// NodeByWireGuardString returns the node ID of the peer whose
// [key.NodePublic.WireGuardGoString] form is s (e.g. "peer(IMTB…r7lM)").
// ok is false if no current peer matches.
func (nb *nodeBackend) NodeByWireGuardString(s string) (_ tailcfg.NodeID, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nid, ok := nb.nodeByWGString[s]
	return nid, ok
}

func (nb *nodeBackend) NodeByID(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.nodeByIDLocked(id)
}

// nodeByIDLocked returns the node (peer or self) with the given node
// ID. nb.mu must be held.
func (nb *nodeBackend) nodeByIDLocked(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	if nb.netMap != nil {
		if self := nb.netMap.SelfNode; self.Valid() && self.ID() == id {
			return self, true
		}
	}
	n, ok := nb.peers[id]
	return n, ok
}

func (nb *nodeBackend) PeerByStableID(id tailcfg.StableNodeID) (_ tailcfg.NodeView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nid, ok := nb.nodeByStableID[id]; ok {
		n, ok := nb.peers[nid]
		return n, ok
	}
	return tailcfg.NodeView{}, false
}

func (nb *nodeBackend) UserByID(id tailcfg.UserID) (_ tailcfg.UserProfileView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	u, ok := nb.userProfiles[id]
	return u, ok
}

// Peers returns all the current peers in an undefined order.
func (nb *nodeBackend) Peers() []tailcfg.NodeView {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return slicesx.MapValues(nb.peers)
}

// PeerByID returns the current state of the peer (not self) node with
// the given ID, or ok=false if it is not a current peer.
func (nb *nodeBackend) PeerByID(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	n, ok := nb.peers[id]
	return n, ok
}

// peerDiscoKeys returns the disco public keys of all current peers,
// keyed by their node public keys. Peers without a disco key are
// omitted.
func (nb *nodeBackend) peerDiscoKeys() map[key.NodePublic]key.DiscoPublic {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	m := make(map[key.NodePublic]key.DiscoPublic, len(nb.peers))
	for _, p := range nb.peers {
		if dk := p.DiscoKey(); !dk.IsZero() {
			m[p.Key()] = dk
		}
	}
	return m
}

func (nb *nodeBackend) PeersForTest() []tailcfg.NodeView {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	ret := slicesx.MapValues(nb.peers)
	slices.SortFunc(ret, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return ret
}

func (nb *nodeBackend) CollectServices() bool {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.netMap != nil && nb.netMap.CollectServices
}

// AppendMatchingPeers returns base with all peers that match pred appended.
//
// It acquires nb.mu to snapshot the peers but releases it before
// calling pred.
func (nb *nodeBackend) AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	nb.mu.Lock()
	peers := slicesx.MapValues(nb.peers)
	nb.mu.Unlock()

	// Sort by node ID for deterministic results; the map iteration
	// above is randomly ordered.
	slices.SortFunc(peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})

	ret := base
	for _, peer := range peers {
		if pred(peer) {
			ret = append(ret, peer)
		}
	}
	return ret
}

// PeerCaps returns the capabilities that remote src IP has to
// ths current node.
func (nb *nodeBackend) PeerCaps(src netip.Addr) tailcfg.PeerCapMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.peerCapsLocked(src)
}

func (nb *nodeBackend) peerCapsLocked(src netip.Addr) tailcfg.PeerCapMap {
	if nb.netMap == nil {
		return nil
	}
	filt := nb.filterAtomic.Load()
	if filt == nil {
		return nil
	}
	addrs := nb.netMap.GetAddresses()
	for i := range addrs.Len() {
		a := addrs.At(i)
		if !a.IsSingleIP() {
			continue
		}
		dst := a.Addr()
		if dst.BitLen() == src.BitLen() { // match on family
			return filt.CapsWithValues(src, dst)
		}
	}
	return nil
}

// PeerCapsForIP returns the capabilities that remote src IP has when
// talking to the given destination IP on this node. The destination may
// be any IP the node handles: its own tailnet address, a VIP service
// address, or any future routable IP.
func (nb *nodeBackend) PeerCapsForIP(src, dst netip.Addr) tailcfg.PeerCapMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return nil
	}
	filt := nb.filterAtomic.Load()
	if filt == nil {
		return nil
	}
	return filt.CapsWithValues(src, dst)
}

// PeerCapsForService returns the capabilities that remote src IP has when
// talking to the named VIP service on this node. The service name is
// resolved to its VIP addresses via the node's service IP mappings, and
// the first address matching the src IP family is used for cap lookup.
func (nb *nodeBackend) PeerCapsForService(src netip.Addr, svcName tailcfg.ServiceName) tailcfg.PeerCapMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return nil
	}
	filt := nb.filterAtomic.Load()
	if filt == nil {
		return nil
	}
	addrs := nb.netMap.GetVIPServiceIPMap()[svcName]
	for _, ip := range addrs {
		if ip.BitLen() == src.BitLen() {
			return filt.CapsWithValues(src, ip)
		}
	}
	return nil
}

// PeerHasCap reports whether the peer contains the given capability string,
// with any value(s).
func (nb *nodeBackend) PeerHasCap(peer tailcfg.NodeView, wantCap tailcfg.PeerCapability) bool {
	if !peer.Valid() {
		return false
	}

	nb.mu.Lock()
	defer nb.mu.Unlock()
	for _, ap := range peer.Addresses().All() {
		if nb.peerHasCapLocked(ap.Addr(), wantCap) {
			return true
		}
	}
	return false
}

func (nb *nodeBackend) peerHasCapLocked(addr netip.Addr, wantCap tailcfg.PeerCapability) bool {
	return nb.peerCapsLocked(addr).HasCapability(wantCap)
}

func (nb *nodeBackend) PeerHasPeerAPI(p tailcfg.NodeView) bool {
	return nb.PeerAPIBase(p) != ""
}

// PeerAPIBase returns the "http://ip:port" URL base to reach peer's PeerAPI,
// or the empty string if the peer is invalid or doesn't support PeerAPI.
func (nb *nodeBackend) PeerAPIBase(p tailcfg.NodeView) string {
	nb.mu.Lock()
	nm := nb.netMap
	nb.mu.Unlock()
	return peerAPIBase(nm, p)
}

// RouteCheckReport is an interface that reports whether a peer is reachable by the current node.
type RouteCheckReport interface {
	// IsReachable reports whether a peer is reachable by the current node.
	IsReachable(tailcfg.NodeID) peernode.Reachability
}

// PeerIsReachable reports whether the current node can reach p.
// This function may return a result based on stale reachability data,
// either from the control plane or because the latest routecheck report is old.
// If rp is nil, then this will report whether p is connected to the control plane
// according to [tailcfg.NodeView.Online].
//
// The latest routecheck report will be considered if the current node has both
// [tailcfg.NodeAttrClientSideReachability] and [tailcfg.NodeAttrClientSideReachabilityRouteCheck]
// in its CapMap.
func (nb *nodeBackend) PeerIsReachable(rp RouteCheckReport, p tailcfg.NodeView) bool {
	nb.mu.Lock()
	nm := nb.netMap
	nb.mu.Unlock()

	if nm == nil || !p.Valid() {
		// If there is no netmap, then how did we get a NodeView?
		// Assuming that p came from the control plane,
		// report whether it was connected to tailcontrol.
		return p.Valid() && p.Online().Get()
	}

	self := nm.SelfNode
	useRouteCheck := isRouteCheckEnabled(self)

	if !useRouteCheck && !self.HasCap(tailcfg.NodeAttrClientSideReachability) {
		// Legacy behavior is to always trust the control plane, which
		// isn’t always correct because the peer could be slow to check
		// in so that control marks it as offline.
		// See tailscale/corp#32686.
		return p.Online().Get()
	}

	if self.Valid() && self.ID() == p.ID() {
		// This node can always reach itself.
		return true
	}

	if !useRouteCheck && !self.HasCap(tailcfg.NodeAttrClientSideReachabilityRouteCheck) {
		// TODO(sfllaw): The following does not actually test for client-side
		// reachability. This would require a mechanism that tracks whether the
		// current node can actually reach this peer, either because they are
		// already communicating or because they can ping each other.
		//
		// Instead, it makes the client ignore p.Online completely.
		//
		// See tailscale/corp#32686.
		return true
	}

	if rp == nil {
		// The routecheck report hasn’t been collected yet,
		// so fall back and report whether it was connected to tailcontrol.
		return p.Online().Get()
	}
	r := rp.IsReachable(p.ID())
	if r == peernode.Unknown {
		// Reachability is unknown, because the node is a new router, so fall back.
		return p.Online().Get()
	}
	return r.IsReachable()
}

func nodeIP(n tailcfg.NodeView, pred func(netip.Addr) bool) netip.Addr {
	for _, pfx := range n.Addresses().All() {
		if pfx.IsSingleIP() && pred(pfx.Addr()) {
			return pfx.Addr()
		}
	}
	return netip.Addr{}
}

func (nb *nodeBackend) NetMap() *netmap.NetworkMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.netMap
}

func (nb *nodeBackend) netMapWithPeers() *netmap.NetworkMap {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return nil
	}
	nm := new(*nb.netMap) // shallow clone
	nm.Peers = slicesx.MapValues(nb.peers)
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	nm.UserProfiles = maps.Clone(nb.userProfiles)
	nm.PacketFilterRules = nb.packetFilterRules
	nm.PacketFilter = nb.packetFilter
	return nm
}

func (nb *nodeBackend) SetNetMap(nm *netmap.NetworkMap) (discoChanged []key.NodePublic, routeChanged routemanager.PeersWithRouteChanges) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.netMap = nm
	nb.updateNodeByAddrLocked()
	nb.updateNodeByKeyLocked()
	nb.updateNodeByStableIDLocked()
	nb.updateNodeByNameLocked()
	discoChanged, routeChanged = nb.updatePeersLocked()
	nb.signalKeyWaitersForTestLocked()
	if nm != nil {
		nb.userProfiles = maps.Clone(nm.UserProfiles)
		nb.packetFilterRules = nm.PacketFilterRules
		nb.packetFilter = nm.PacketFilter
		nb.derpMapViewPub.Publish(nm.DERPMap.View())
	} else {
		nb.userProfiles = nil
		nb.packetFilterRules = views.Slice[tailcfg.FilterRule]{}
		nb.packetFilter = nil
		nb.derpMapViewPub.Publish(tailcfg.DERPMapView{})
	}
	return discoChanged, routeChanged
}

// AwaitNodeKeyForTest returns a channel that is closed once a peer with the
// given node key first appears in this nodeBackend's peer index, or
// immediately (a closed channel) if it's already present. It is intended for
// in-process benchmarks that drive synthetic netmap deltas and need a
// zero-overhead signal that the client has applied a delta, replacing
// poll-based [local.Client.WhoIsNodeKey] loops in tests. It panics outside
// of tests.
func (nb *nodeBackend) AwaitNodeKeyForTest(k key.NodePublic) <-chan struct{} {
	testenv.AssertInTest()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if _, ok := nb.nodeByKey[k]; ok {
		return syncs.ClosedChan()
	}
	if ch, ok := nb.keyWaitersForTest[k]; ok {
		return ch
	}
	ch := make(chan struct{})
	mak.Set(&nb.keyWaitersForTest, k, ch)
	return ch
}

// signalKeyWaitersForTestLocked closes any waiter channels whose keys now
// appear in nb.nodeByKey. It is cheap when there are no waiters, which is
// the common case in production. It is called from [nodeBackend.SetNetMap]
// after the per-key index has been rebuilt.
//
// Caller must hold nb.mu.
func (nb *nodeBackend) signalKeyWaitersForTestLocked() {
	for k, ch := range nb.keyWaitersForTest {
		if _, ok := nb.nodeByKey[k]; ok {
			close(ch)
			delete(nb.keyWaitersForTest, k)
		}
	}
}

func (nb *nodeBackend) updateNodeByAddrLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.nodeByAddr = nil
		return
	}

	addNodeAddr := func(n tailcfg.NodeView) {
		for _, ipp := range n.Addresses().All() {
			if ipp.IsSingleIP() {
				nb.nodeByAddr[ipp.Addr()] = n.ID()
			}
		}
	}
	mapx.RepopulateNonzero(&nb.nodeByAddr, func() {
		if nm.SelfNode.Valid() {
			addNodeAddr(nm.SelfNode)
		}
		for _, p := range nm.Peers {
			addNodeAddr(p)
		}
	})
}

func (nb *nodeBackend) updateNodeByKeyLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.nodeByKey = nil
		nb.nodeByWGString = nil
		return
	}

	mapx.RepopulateNonzero(&nb.nodeByKey, func() {
		if nm.SelfNode.Valid() {
			nb.nodeByKey[nm.SelfNode.Key()] = nm.SelfNode.ID()
		}
		for _, p := range nm.Peers {
			nb.nodeByKey[p.Key()] = p.ID()
		}
	})
	mapx.RepopulateNonzero(&nb.nodeByWGString, func() {
		if nm.SelfNode.Valid() {
			nb.nodeByWGString[nm.SelfNode.Key().WireGuardGoString()] = nm.SelfNode.ID()
		}
		for _, p := range nm.Peers {
			nb.nodeByWGString[p.Key().WireGuardGoString()] = p.ID()
		}
	})
}

func (nb *nodeBackend) updateNodeByStableIDLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.nodeByStableID = nil
		return
	}

	mapx.RepopulateNonzero(&nb.nodeByStableID, func() {
		for _, p := range nm.Peers {
			nb.nodeByStableID[p.StableID()] = p.ID()
		}
	})
}

// addNodeNameLocked adds both the FQDN and short-name keys for the given
// node to nb.nodeByName. nb.mu must be held.
func (nb *nodeBackend) addNodeNameLocked(name string, nid tailcfg.NodeID) {
	if name == "" {
		// We might support name-less nodes in the future; tailscale/corp#43949
		return
	}
	canon := strings.ToLower(strings.TrimSuffix(name, "."))
	mak.Set(&nb.nodeByName, canon, nid)
	if suffix := nb.netMap.MagicDNSSuffix(); dnsname.HasSuffix(canon, suffix) {
		mak.Set(&nb.nodeByName, dnsname.TrimSuffix(canon, suffix), nid)
	}
}

// removeNodeNameLocked removes both the FQDN and short-name keys for the
// given node from nb.nodeByName. nb.mu must be held.
func (nb *nodeBackend) removeNodeNameLocked(name string) {
	if name == "" {
		// We might support name-less nodes in the future; tailscale/corp#43949
		return
	}
	canon := strings.ToLower(strings.TrimSuffix(name, "."))
	delete(nb.nodeByName, canon)
	if suffix := nb.netMap.MagicDNSSuffix(); dnsname.HasSuffix(canon, suffix) {
		delete(nb.nodeByName, dnsname.TrimSuffix(canon, suffix))
	}
}

func (nb *nodeBackend) updateNodeByNameLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.nodeByName = nil
		nb.extraDNS = nil
		return
	}

	mapx.RepopulateNonzero(&nb.nodeByName, func() {
		if nm.SelfNode.Valid() {
			nb.addNodeNameLocked(nm.SelfNode.Name(), nm.SelfNode.ID())
		}
		for _, p := range nm.Peers {
			nb.addNodeNameLocked(p.Name(), p.ID())
		}
	})

	// Rebuild extraDNS from DNS.ExtraRecords (service VIPs, etc).
	nb.extraDNS = nil
	for _, rec := range nm.DNS.ExtraRecords {
		if rec.Type != "" {
			continue
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			continue
		}
		mak.Set(&nb.extraDNS, strings.ToLower(strings.TrimSuffix(rec.Name, ".")), ip)
	}
}

// NodeByName returns the node ID for a MagicDNS hostname. The input
// must be lowercase with no trailing dot; both short names ("foo") and
// FQDNs ("foo.tail-scale.ts.net") are accepted.
func (nb *nodeBackend) NodeByName(hostname string) (_ tailcfg.NodeID, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nid, ok := nb.nodeByName[hostname]
	return nid, ok
}

// ExtraDNSByName returns the IP for a DNS.ExtraRecords entry (e.g. service VIPs).
func (nb *nodeBackend) ExtraDNSByName(hostname string) (_ netip.Addr, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	ip, ok := nb.extraDNS[hostname]
	return ip, ok
}

func (nb *nodeBackend) updatePeersLocked() (discoChanged []key.NodePublic, routeChanged routemanager.PeersWithRouteChanges) {
	nm := nb.netMap
	oldIDs := slices.Collect(maps.Keys(nb.peers))

	// Snapshot the previous disco keys (by node key) before the peers
	// map is repopulated, to detect restarted peers below.
	var prevDisco map[key.NodePublic]key.DiscoPublic
	for _, p := range nb.peers {
		if !p.DiscoKey().IsZero() {
			mak.Set(&prevDisco, p.Key(), p.DiscoKey())
		}
	}

	if nm == nil {
		nb.peers = nil
	} else {
		mapx.RepopulateNonzero(&nb.peers, func() {
			for _, p := range nm.Peers {
				nb.peers[p.ID()] = p
			}
		})
	}

	for _, p := range nb.peers {
		if prev, ok := prevDisco[p.Key()]; ok && nb.discoChangedLocked(p.Key(), prev, p.DiscoKey()) {
			discoChanged = append(discoChanged, p.Key())
		}
	}
	// Drop TSMP-learned disco keys for peers no longer in the netmap.
	for k := range nb.tsmpLearnedDisco {
		if _, ok := nb.nodeByKey[k]; !ok {
			delete(nb.tsmpLearnedDisco, k)
		}
	}

	// Resync the route manager to the new peer set. Upserts of
	// unchanged peers are cheap no-ops; this is a full-netmap event,
	// so O(n) work is expected here.
	rt := nb.routeMgr.Begin()
	for _, id := range oldIDs {
		if _, ok := nb.peers[id]; !ok {
			rt.RemovePeer(id)
		}
	}
	for _, p := range nb.peers {
		rt.UpsertPeer(p)
	}
	res := rt.Commit()
	return discoChanged, res.AllowedIPs
}

// recordTSMPLearnedDisco notes that a peer's new disco key was learned via
// TSMP, so the netmap update carrying the same change need not reset the
// peer's WireGuard session. See the [nodeBackend.tsmpLearnedDisco] field doc.
func (nb *nodeBackend) recordTSMPLearnedDisco(pub key.NodePublic, disco key.DiscoPublic) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	mak.Set(&nb.tsmpLearnedDisco, pub, disco)
}

// discoChangedLocked reports whether a peer's disco key change from prev to
// cur should reset the peer's WireGuard session. A changed disco key means
// the peer restarted, so any existing session key material is dead weight;
// resetting lets the handshake start over immediately. The exception is a
// key change already learned via TSMP: that arrived over a working WireGuard
// session with the peer, so the session is demonstrably fine and is kept.
//
// It consumes any [nodeBackend.tsmpLearnedDisco] entry for pub.
// nb.mu must be held.
func (nb *nodeBackend) discoChangedLocked(pub key.NodePublic, prev, cur key.DiscoPublic) bool {
	if prev.IsZero() || cur.IsZero() || prev == cur {
		return false
	}
	if discoTSMP, ok := nb.tsmpLearnedDisco[pub]; ok {
		delete(nb.tsmpLearnedDisco, pub)
		if discoTSMP == cur {
			nb.logf("nodeBackend: skipping WireGuard session reset (TSMP key): %s changed from %q to %q",
				pub.ShortString(), prev, cur)
			return false
		}
		// The new disco key does not match what we received via
		// TSMP for this peer. This is unexpected, though possible
		// if processing a change in a large netmap ends up taking
		// longer than the 2 second timeout in
		// [controlclient.mapRoutineState.UpdateNetmapDelta], or if
		// the context is cancelled mid update. Log the event, and reset
		// the session as it is possibly a stale entry in the map
		// instead of a TSMP disco key update that led us here.
		nb.logf("nodeBackend: [unexpected] using TSMP key for %s (control stale): tsmp=%q control=%q old=%q",
			pub.ShortString(), discoTSMP, cur, prev)
		metricTSMPLearnedKeyMismatch.Add(1)
	}
	nb.logf("nodeBackend: peer %s disco key changed from %q to %q", pub.ShortString(), prev, cur)
	return true
}

// routePrefs is the subset of routing-relevant prefs (and derived
// state) that [nodeBackend.updateRouteManagerPrefs] pushes into the
// RouteManager.
type routePrefs struct {
	// ExitNodeID is the stable node ID of the selected exit node, or
	// zero if none is selected.
	ExitNodeID tailcfg.StableNodeID

	// ExitNodeSelected is whether the prefs select any exit node at
	// all, even one that doesn't resolve (e.g. an ExitNodeIP that
	// never resolved to an ExitNodeID); it mirrors
	// routerConfigLocked's blackhole condition.
	ExitNodeSelected bool

	// RouteAll is whether advertised subnet routes from peers are
	// accepted.
	RouteAll bool

	// OneCGNAT is whether the OS route set should collapse peers'
	// CGNAT addresses into the single /10 route.
	OneCGNAT bool
}

// updateRouteManagerPrefs pushes p into the route manager.
//
// It returns the peers whose allowed source prefixes changed as a
// result, for example the old and new exit node when the selection
// changes.
func (nb *nodeBackend) updateRouteManagerPrefs(p routePrefs) routemanager.PeersWithRouteChanges {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	var exitID tailcfg.NodeID
	if !p.ExitNodeID.IsZero() {
		// The lookup can miss: the selected exit node may not exist,
		// or may be a placeholder like MDM's "auto:any" awaiting
		// resolution. ExitNodeSelected then makes the RouteManager
		// blackhole internet traffic rather than treat it as "no
		// exit node"; see [routemanager.Prefs.ExitNodeSelected].
		exitID = nb.nodeByStableID[p.ExitNodeID]
	}
	rt := nb.routeMgr.Begin()
	rt.SetPrefs(routemanager.Prefs{
		ExitNodeID:       exitID,
		ExitNodeSelected: p.ExitNodeSelected,
		RouteAll:         p.RouteAll,
	})
	rt.SetTailnetConfig(routemanager.TailnetConfig{OneCGNAT: p.OneCGNAT})
	res := rt.Commit()
	return res.AllowedIPs
}

// updateRouteManagerExtras pushes extra WireGuard-only allowed IPs
// into the route manager, obtained by calling fn (the
// [ipnext.Hooks.ExtraWireGuardAllowedIPs] hook) with a sequence of
// the current peers.
//
// It returns the peers whose allowed source prefixes changed as a
// result.
func (nb *nodeBackend) updateRouteManagerExtras(fn func(peers iter.Seq2[tailcfg.NodeID, key.NodePublic]) map[tailcfg.NodeID][]netip.Prefix) routemanager.PeersWithRouteChanges {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	extras := fn(func(yield func(tailcfg.NodeID, key.NodePublic) bool) {
		for id, p := range nb.peers {
			if !yield(id, p.Key()) {
				return
			}
		}
	})
	rt := nb.routeMgr.Begin()
	rt.SetExtraAllowedIPs(extras)
	res := rt.Commit()
	return res.AllowedIPs
}

// osRoutes returns the sorted set of prefixes that the route manager
// wants programmed into the OS routing table.
func (nb *nodeBackend) osRoutes() []netip.Prefix {
	var routes []netip.Prefix
	for pfx := range nb.routeMgr.OSRoutes().All() {
		routes = append(routes, pfx)
	}
	tsaddr.SortPrefixes(routes)
	return routes
}

// setPacketFilter stores the live packet filter rules and parsed
// matches. It does not touch the frozen netMap. nb.mu is acquired by
// this method.
func (nb *nodeBackend) setPacketFilter(rules views.Slice[tailcfg.FilterRule], parsed []filter.Match) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.packetFilterRules = rules
	nb.packetFilter = parsed
}

// PacketFilter returns the current live packet filter matches.
func (nb *nodeBackend) PacketFilter() []filter.Match {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetFilter
}

// mergeUserProfiles merges new/updated [tailcfg.UserProfileView]
// entries into the live userProfiles map. It does not touch
// netMap.UserProfiles (which is frozen once set). Callers must hold
// [LocalBackend.mu]. nb.mu is acquired by this method.
func (nb *nodeBackend) mergeUserProfiles(profiles map[tailcfg.UserID]tailcfg.UserProfileView) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	for id, up := range profiles {
		mak.Set(&nb.userProfiles, id, up)
	}
}

// netmapDeltaResult describes the side effects of applying netmap
// delta mutations that the caller must propagate.
type netmapDeltaResult struct {
	// ChangedAllowedIPs are the peers whose allowed source prefixes
	// changed; the caller syncs those peers to the WireGuard device.
	ChangedAllowedIPs routemanager.PeersWithRouteChanges

	// DiscoChanged is the set of peers whose disco key changed in a
	// way that requires a WireGuard session reset (see
	// [nodeBackend.discoChangedLocked]).
	DiscoChanged set.Set[key.NodePublic]
}

// UpdateNetmapDelta applies the given netmap mutations to the live
// peer state. It returns the side effects for the caller to
// propagate, and reports whether it handled all of the mutations.
func (nb *nodeBackend) UpdateNetmapDelta(muts []netmap.NodeMutation) (res netmapDeltaResult, handled bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil {
		return res, false
	}

	// Locally cloned mutable nodes, to avoid calling AsStruct (clone)
	// multiple times on a node if it's mutated multiple times in this
	// call (e.g. its endpoints + online status both change)
	var mutableNodes map[tailcfg.NodeID]*tailcfg.Node

	// Mirror peer add/remove mutations into the route manager.
	// The Commit is unconditional (even if we panic or return false)
	// to stay in sync with the peers map, which is likewise mutated
	// in place as the loop runs. And if we return false, we'll just
	// get a full netmap soon and reset all our state anyway.
	rt := nb.routeMgr.Begin()
	defer func() {
		res.ChangedAllowedIPs = rt.Commit().AllowedIPs
	}()

	for _, m := range muts {
		switch m := m.(type) {
		case netmap.NodeMutationUpsert:
			nid := m.Node.ID()
			if old, ok := nb.peers[nid]; ok {
				if old.Key() == m.Node.Key() {
					if nb.discoChangedLocked(m.Node.Key(), old.DiscoKey(), m.Node.DiscoKey()) {
						res.DiscoChanged.Make()
						res.DiscoChanged.Add(m.Node.Key())
					}
				} else {
					delete(nb.tsmpLearnedDisco, old.Key())
				}
			}
			mak.Set(&nb.peers, nid, m.Node)
			for _, ipp := range m.Node.Addresses().All() {
				if ipp.IsSingleIP() {
					mak.Set(&nb.nodeByAddr, ipp.Addr(), nid)
				}
			}
			mak.Set(&nb.nodeByKey, m.Node.Key(), nid)
			mak.Set(&nb.nodeByWGString, m.Node.Key().WireGuardGoString(), nid)
			mak.Set(&nb.nodeByStableID, m.Node.StableID(), nid)
			nb.addNodeNameLocked(m.Node.Name(), nid)
			rt.UpsertPeer(m.Node)
			continue
		case netmap.NodeMutationRemove:
			nid := m.NodeIDBeingMutated()
			if old, ok := nb.peers[nid]; ok {
				for _, ipp := range old.Addresses().All() {
					if ipp.IsSingleIP() {
						delete(nb.nodeByAddr, ipp.Addr())
					}
				}
				delete(nb.nodeByKey, old.Key())
				delete(nb.nodeByWGString, old.Key().WireGuardGoString())
				delete(nb.nodeByStableID, old.StableID())
				delete(nb.tsmpLearnedDisco, old.Key())
				nb.removeNodeNameLocked(old.Name())
				delete(nb.peers, nid)
				rt.RemovePeer(nid)
			}
			continue
		}
		// Per-field mutation.
		nid := m.NodeIDBeingMutated()
		n, ok := mutableNodes[nid]
		if !ok {
			nv, ok := nb.peers[nid]
			if !ok {
				// TODO(bradfitz): unexpected metric?
				return res, false
			}
			n = nv.AsStruct()
			mak.Set(&mutableNodes, nv.ID(), n)
		}
		m.Apply(n)
	}
	for nid, n := range mutableNodes {
		nb.peers[nid] = n.View()
	}
	nb.signalKeyWaitersForTestLocked()
	return res, true
}

// unlockedNodesPermitted reports whether any peer with theUnsignedPeerAPIOnly bool set true has any of its allowed IPs
// in the specified packet filter.
//
// TODO(nickkhyl): It is here temporarily until we can move the whole [LocalBackend.updateFilterLocked] here,
// but change it so it builds and returns a filter for the current netmap/prefs instead of re-configuring the engine filter.
// Something like (*nodeBackend).RebuildFilters() (filter, jailedFilter *filter.Filter, changed bool) perhaps?
func (nb *nodeBackend) unlockedNodesPermitted(packetFilter []filter.Match) bool {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return packetFilterPermitsUnlockedNodes(nb.peers, packetFilter)
}

func (nb *nodeBackend) filter() *filter.Filter {
	return nb.filterAtomic.Load()
}

func (nb *nodeBackend) setFilter(f *filter.Filter) {
	nb.filterAtomic.Store(f)
}

func (nb *nodeBackend) dnsConfigForNetmap(prefs ipn.PrefsView, selfExpired bool, goos string) *dns.Config {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return dnsConfigForNetmap(nb.netMap, nb.peers, prefs, selfExpired, nb.logf, goos)
}

// magicDNSHostAddrs returns the MagicDNS A/AAAA answer for fqdn from
// the live node indexes, and whether the name is known. It backs
// [resolver.MagicDNSHosts.LookupHost], replacing the full
// dns.Config.Hosts map so that netmap deltas need no per-peer DNS
// rebuild.
func (nb *nodeBackend) magicDNSHostAddrs(fqdn dnsname.FQDN) (ips []netip.Addr, ok bool) {
	if !buildfeatures.HasDNS {
		return nil, false
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	n, ok := nb.nodeByFQDNLocked(fqdn)
	if !ok || n.Addresses().Len() == 0 {
		return nil, false
	}
	nm := nb.netMap
	var flags magicDNSAddrsFlags
	if nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs6) &&
		!nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs4) {
		flags |= selfV6Only
	}
	if nm.AllCaps.Contains(tailcfg.NodeAttrMagicDNSPeerAAAA) {
		flags |= wantAAAA
	}
	return magicDNSAddrs(n.Addresses(), flags), true
}

// magicDNSPTR returns the MagicDNS name of the node (peer or self)
// that owns ip, backing [resolver.MagicDNSHosts.LookupPTR].
func (nb *nodeBackend) magicDNSPTR(ip netip.Addr) (_ dnsname.FQDN, ok bool) {
	if !buildfeatures.HasDNS {
		return "", false
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nid, ok := nb.nodeByAddr[ip]
	if !ok {
		return "", false
	}
	n, ok := nb.nodeByIDLocked(nid)
	if !ok {
		return "", false
	}
	fqdn, err := dnsname.ToFQDN(n.Name())
	if err != nil {
		return "", false
	}
	return fqdn, true
}

// magicDNSSubdomainHost reports whether fqdn names a node with the
// [tailcfg.NodeAttrDNSSubdomainResolve] attribute, backing
// [resolver.MagicDNSHosts.SubdomainHost].
func (nb *nodeBackend) magicDNSSubdomainHost(fqdn dnsname.FQDN) bool {
	if !buildfeatures.HasDNS {
		return false
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	n, ok := nb.nodeByFQDNLocked(fqdn)
	if !ok {
		return false
	}
	if nm := nb.netMap; nm != nil && nm.SelfNode.Valid() && nm.SelfNode.ID() == n.ID() {
		return nm.AllCaps.Contains(tailcfg.NodeAttrDNSSubdomainResolve)
	}
	return n.CapMap().Contains(tailcfg.NodeAttrDNSSubdomainResolve)
}

// nodeByFQDNLocked returns the node (peer or self) with the given
// MagicDNS FQDN. nb.mu must be held.
func (nb *nodeBackend) nodeByFQDNLocked(fqdn dnsname.FQDN) (_ tailcfg.NodeView, ok bool) {
	// The resolver already lowercases query names, but lowercase
	// again (nearly free when already lowercase) so that no other
	// caller of the [resolver.MagicDNSHosts] hook can miss on case.
	nid, ok := nb.nodeByName[strings.ToLower(strings.TrimSuffix(string(fqdn), "."))]
	if !ok {
		return tailcfg.NodeView{}, false
	}
	return nb.nodeByIDLocked(nid)
}

// magicDNSAddrsFlags is a bitmask of flags for magicDNSAddrs.
type magicDNSAddrsFlags uint8

const (
	selfV6Only magicDNSAddrsFlags = 1 << iota // the querying node has only IPv6 addresses
	wantAAAA                                  // include IPv6 addresses even for nodes that also have IPv4
)

// magicDNSAddrs returns the MagicDNS answer addresses for a node
// owning the given addresses: all of its IPv6 addresses if this node
// (the querier) is IPv6-only, otherwise everything except the node's
// IPv6 addresses when it also has IPv4, unless wantAAAA. The result
// may be empty (name exists, no records of the desired family).
func magicDNSAddrs(addrs views.Slice[netip.Prefix], flags magicDNSAddrsFlags) (ips []netip.Addr) {
	wantAAAA := flags&wantAAAA != 0
	selfV6Only := flags&selfV6Only != 0
	var have4 bool
	for _, addr := range addrs.All() {
		if addr.Addr().Is4() {
			have4 = true
			break
		}
	}
	for _, addr := range addrs.All() {
		if selfV6Only {
			if addr.Addr().Is6() {
				ips = append(ips, addr.Addr())
			}
			continue
		}
		// If this node has an IPv4 address, then remove peers'
		// IPv6 addresses for now, as we don't guarantee that
		// the peer node actually can speak IPv6 correctly.
		//
		// https://github.com/tailscale/tailscale/issues/1152
		// tracks adding the right capability reporting to
		// enable AAAA in MagicDNS.
		if addr.Addr().Is6() && have4 && !wantAAAA {
			continue
		}
		ips = append(ips, addr.Addr())
	}
	return ips
}

func (nb *nodeBackend) exitNodeCanProxyDNS(exitNodeID tailcfg.StableNodeID) (dohURL string, ok bool) {
	if !buildfeatures.HasUseExitNode {
		return "", false
	}
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return exitNodeCanProxyDNS(nb.netMap, nb.peers, exitNodeID)
}

// ready signals that [LocalBackend] has completed the switch to this [nodeBackend]
// and any pending calls to [nodeBackend.Wait] must be unblocked.
func (nb *nodeBackend) ready() {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.readyCh != nil {
		close(nb.readyCh)
	}
}

// Wait blocks until [LocalBackend] completes the switch to this [nodeBackend]
// and calls [nodeBackend.ready]. It returns an error if the provided context
// is canceled or if the [nodeBackend] shuts down or is already shut down.
//
// It must not be called with the [LocalBackend]'s internal mutex held as [LocalBackend]
// may need to acquire it to complete the switch.
//
// TODO(nickkhyl): Relax this restriction once [LocalBackend]'s state machine
// runs in its own goroutine, or if we decide that waiting for the state machine
// restart to finish isn't necessary for [LocalBackend] to consider the switch complete.
// We mostly need this because of [LocalBackend.Start] acquiring b.mu and the fact that
// methods like [LocalBackend.SwitchProfile] must report any errors returned by it.
// Perhaps we could report those errors asynchronously as [health.Warnable]s?
func (nb *nodeBackend) Wait(ctx context.Context) error {
	nb.mu.Lock()
	readyCh := nb.readyCh
	nb.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-nb.ctx.Done():
		return context.Cause(nb.ctx)
	case <-readyCh:
		return nil
	}
}

// shutdown shuts down the [nodeBackend] and cancels its context
// with the provided cause.
func (nb *nodeBackend) shutdown(cause error) {
	nb.shutdownOnce.Do(func() {
		nb.doShutdown(cause)
	})
}

func (nb *nodeBackend) doShutdown(cause error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.ctxCancel(cause)
	nb.readyCh = nil
	nb.eventClient.Close()
}

// useWithExitNodeResolvers filters out resolvers so the ones that remain
// are all the ones marked for use with exit nodes.
func useWithExitNodeResolvers(resolvers []*dnstype.Resolver) []*dnstype.Resolver {
	var filtered []*dnstype.Resolver
	for _, res := range resolvers {
		if res.UseWithExitNode {
			filtered = append(filtered, res)
		}
	}
	return filtered
}

// useWithExitNodeRoutes filters out routes so the ones that remain
// are either zero-length resolver lists, or lists containing only
// resolvers marked for use with exit nodes.
func useWithExitNodeRoutes(routes map[string][]*dnstype.Resolver) map[string][]*dnstype.Resolver {
	var filtered map[string][]*dnstype.Resolver
	for suffix, resolvers := range routes {
		// Suffixes with no resolvers represent a valid configuration,
		// and should persist regardless of exit node considerations.
		if len(resolvers) == 0 {
			mak.Set(&filtered, suffix, make([]*dnstype.Resolver, 0))
			continue
		}

		// In exit node contexts, we filter out resolvers not configured for use with
		// exit nodes. If there are no such configured resolvers, there should not be an entry for that suffix.
		filteredResolvers := useWithExitNodeResolvers(resolvers)
		if len(filteredResolvers) > 0 {
			mak.Set(&filtered, suffix, filteredResolvers)
		}
	}

	return filtered
}

// dnsConfigForNetmap returns a *dns.Config for the given netmap,
// prefs, client OS version, and cloud hosting environment.
//
// The goos is runtime.GOOS usually, except in tests, where it may
// vary to test any OS's behavior from any host.
func dnsConfigForNetmap(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, prefs ipn.PrefsView, selfExpired bool, logf logger.Logf, goos string) *dns.Config {
	if nm == nil {
		return nil
	}
	if !buildfeatures.HasDNS {
		return &dns.Config{}
	}

	// If the current node's key is expired, then we don't program any DNS
	// configuration into the operating system. This ensures that if the
	// DNS configuration specifies a DNS server that is only reachable over
	// Tailscale, we don't break connectivity for the user.
	//
	// TODO(andrew-d): this also stops returning anything from quad-100; we
	// could do the same thing as having "CorpDNS: false" and keep that but
	// not program the OS?
	if selfExpired {
		return &dns.Config{}
	}

	dcfg := &dns.Config{
		AcceptDNS: prefs.CorpDNS(),
		Routes:    map[dnsname.FQDN][]*dnstype.Resolver{},
		Hosts:     map[dnsname.FQDN][]netip.Addr{},
	}

	var addrFlags magicDNSAddrsFlags
	if nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs6) &&
		!nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs4) {
		// We only have IPv6 addresses ourselves.
		addrFlags |= selfV6Only
		dcfg.OnlyIPv6 = true
	}
	if nm.AllCaps.Contains(tailcfg.NodeAttrMagicDNSPeerAAAA) {
		addrFlags |= wantAAAA
	}

	// Populate MagicDNS records. The internal quad-100 resolver pulls
	// per-node records on demand from the live node indexes (see
	// [nodeBackend.magicDNSHostAddrs]), so quad-100 can always respond
	// to MagicDNS queries without dcfg.Hosts; details in
	// https://github.com/tailscale/tailscale/issues/1886. dcfg.Hosts
	// carries only what must be enumerable in full: control's
	// DNS.ExtraRecords below, plus every node's records on Windows,
	// whose hosts-file fallback path (see compileHostEntries in
	// net/dns) needs the complete set.
	if goos == "windows" {
		set := func(name string, addrs views.Slice[netip.Prefix]) {
			if addrs.Len() == 0 || name == "" {
				return
			}
			fqdn, err := dnsname.ToFQDN(name)
			if err != nil {
				return // TODO: propagate error?
			}
			dcfg.Hosts[fqdn] = magicDNSAddrs(addrs, addrFlags)
		}
		set(nm.SelfName(), nm.GetAddresses())
		for _, peer := range peers {
			set(peer.Name(), peer.Addresses())
		}
	}
	for _, rec := range nm.DNS.ExtraRecords {
		switch rec.Type {
		case "", "A", "AAAA":
			// Treat these all the same for now: infer from the value
		default:
			// TODO: more
			continue
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			// Ignore.
			continue
		}
		fqdn, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		dcfg.Hosts[fqdn] = append(dcfg.Hosts[fqdn], ip)
	}

	if !prefs.CorpDNS() {
		return dcfg
	}

	for _, dom := range nm.DNS.Domains {
		fqdn, err := dnsname.ToFQDN(dom)
		if err != nil {
			logf("[unexpected] non-FQDN search domain %q", dom)
		}
		dcfg.SearchDomains = append(dcfg.SearchDomains, fqdn)
	}
	if nm.DNS.Proxied { // actually means "enable MagicDNS"
		for _, dom := range magicDNSRootDomains(nm) {
			dcfg.Routes[dom] = nil // resolve internally with dcfg.Hosts
		}
	} else {
		// Without MagicDNS domain routing, no Routes entry covers the
		// node records served on demand via [magicDNSHosts]. Tell
		// dns.Manager they exist, so it keeps quad-100 in the OS
		// resolver path and the names still resolve, as they did when
		// they were listed in dcfg.Hosts. Any netmap with a self node
		// has such records.
		dcfg.MagicDNSHostsUnrouted = nm.SelfNode.Valid()
	}

	addDefault := func(resolvers []*dnstype.Resolver) {
		dcfg.DefaultResolvers = append(dcfg.DefaultResolvers, resolvers...)
	}

	addSplitDNSRoutes := func(routes map[string][]*dnstype.Resolver) {
		for suffix, resolvers := range routes {
			fqdn, err := dnsname.ToFQDN(suffix)
			if err != nil {
				logf("[unexpected] non-FQDN route suffix %q", suffix)
			}

			// Create map entry even if len(resolvers) == 0; Issue 2706.
			// This lets the control plane send ExtraRecords for which we
			// can authoritatively answer "name not exists" for when the
			// control plane also sends this explicit but empty route
			// making it as something we handle.
			dcfg.Routes[fqdn] = slices.Clone(resolvers)
		}
	}

	// If we're using an exit node and that exit node is new enough (1.19.x+)
	// to run a DoH DNS proxy, then send all our DNS traffic through it,
	// unless we find resolvers with UseWithExitNode set, in which case we use that.
	if buildfeatures.HasUseExitNode {
		if dohURL, ok := exitNodeCanProxyDNS(nm, peers, prefs.ExitNodeID()); ok {
			filtered := useWithExitNodeResolvers(nm.DNS.Resolvers)
			if len(filtered) > 0 {
				addDefault(filtered)
			} else {
				// If no default global resolvers with the override
				// are configured, configure the exit node's resolver.
				addDefault([]*dnstype.Resolver{{Addr: dohURL}})
			}

			addSplitDNSRoutes(useWithExitNodeRoutes(nm.DNS.Routes))
			return dcfg
		}
	}

	// If the user has set default resolvers ("override local DNS"), prefer to
	// use those resolvers as the default, otherwise if there are WireGuard exit
	// node resolvers, use those as the default.
	if len(nm.DNS.Resolvers) > 0 {
		addDefault(nm.DNS.Resolvers)
	} else if buildfeatures.HasUseExitNode {
		if resolvers, ok := wireguardExitNodeDNSResolvers(nm, peers, prefs.ExitNodeID()); ok {
			addDefault(resolvers)
		}
	}

	// Add split DNS routes, with no regard to exit node configuration.
	addSplitDNSRoutes(nm.DNS.Routes)

	if buildfeatures.HasConn25 && !prefs.AppConnector().Advertise {
		// Add split DNS routes for conn25
		if appRoutes := appc.AppDNSRoutes(nm.HasCap, nm.SelfNode); appRoutes != nil {
			addSplitDNSRoutes(appRoutes)
		}
	}

	// Set FallbackResolvers as the default resolvers in the
	// scenarios that can't handle a purely split-DNS config. See
	// https://github.com/tailscale/tailscale/issues/1743 for
	// details.
	switch {
	case len(dcfg.DefaultResolvers) != 0:
		// Default resolvers already set.
	case !prefs.ExitNodeID().IsZero():
		// When using an exit node, we send all DNS traffic to the exit node, so
		// we don't need a fallback resolver.
		//
		// However, if the exit node is too old to run a DoH DNS proxy, then we
		// need to use a fallback resolver as it's very likely the LAN resolvers
		// will become unreachable.
		//
		// This is especially important on Apple OSes, where
		// adding the default route to the tunnel interface makes
		// it "primary", and we MUST provide VPN-sourced DNS
		// settings or we break all DNS resolution.
		//
		// https://github.com/tailscale/tailscale/issues/1713
		addDefault(nm.DNS.FallbackResolvers)
	case len(dcfg.Routes) == 0:
		// No settings requiring split DNS, no problem.
	}

	return dcfg
}
