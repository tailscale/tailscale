// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"go4.org/netipx"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
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
	// filterAtomic is a stateful packet filter. Immutable once created, but can be
	// replaced with a new one.
	filterAtomic atomic.Pointer[filter.Filter]

	// TODO(nickkhyl): maybe use sync.RWMutex?
	mu sync.Mutex // protects the following fields

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
}

func newNodeBackend() *nodeBackend {
	cn := &nodeBackend{}
	// Default filter blocks everything and logs nothing.
	noneFilter := filter.NewAllowNone(logger.Discard, &netipx.IPSet{})
	cn.filterAtomic.Store(noneFilter)
	return cn
}

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
	if nb.netMap == nil {
		return 0, false
	}
	if self := nb.netMap.SelfNode; self.Valid() && self.Key() == k {
		return self.ID(), true
	}
	// TODO(bradfitz,nickkhyl): add nodeByKey like nodeByAddr instead of walking peers.
	for _, n := range nb.peers {
		if n.Key() == k {
			return n.ID(), true
		}
	}
	return 0, false
}

func (nb *nodeBackend) PeerByID(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	n, ok := nb.peers[id]
	return n, ok
}

func (nb *nodeBackend) PeerByStableID(id tailcfg.StableNodeID) (_ tailcfg.NodeView, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	for _, n := range nb.peers {
		if n.StableID() == id {
			return n, true
		}
	}
	return tailcfg.NodeView{}, false
}

func (nb *nodeBackend) UserByID(id tailcfg.UserID) (_ tailcfg.UserProfileView, ok bool) {
	nb.mu.Lock()
	nm := nb.netMap
	nb.mu.Unlock()
	if nm == nil {
		return tailcfg.UserProfileView{}, false
	}
	u, ok := nm.UserProfiles[id]
	return u, ok
}

// Peers returns all the current peers in an undefined order.
func (nb *nodeBackend) Peers() []tailcfg.NodeView {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return slicesx.MapValues(nb.peers)
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

// AppendMatchingPeers returns base with all peers that match pred appended.
//
// It acquires b.mu to read the netmap but releases it before calling pred.
func (nb *nodeBackend) AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	var peers []tailcfg.NodeView

	nb.mu.Lock()
	if nb.netMap != nil {
		// All fields on b.netMap are immutable, so this is
		// safe to copy and use outside the lock.
		peers = nb.netMap.Peers
	}
	nb.mu.Unlock()

	ret := base
	for _, peer := range peers {
		// The peers in b.netMap don't contain updates made via
		// UpdateNetmapDelta. So only use PeerView in b.netMap for its NodeID,
		// and then look up the latest copy in b.peers which is updated in
		// response to UpdateNetmapDelta edits.
		nb.mu.Lock()
		peer, ok := nb.peers[peer.ID()]
		nb.mu.Unlock()
		if ok && pred(peer) {
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
	nm := ptr.To(*nb.netMap) // shallow clone
	nm.Peers = slicesx.MapValues(nb.peers)
	slices.SortFunc(nm.Peers, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	return nm
}

func (nb *nodeBackend) SetNetMap(nm *netmap.NetworkMap) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.netMap = nm
	nb.updateNodeByAddrLocked()
	nb.updatePeersLocked()
}

func (nb *nodeBackend) updateNodeByAddrLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.nodeByAddr = nil
		return
	}

	// Update the nodeByAddr index.
	if nb.nodeByAddr == nil {
		nb.nodeByAddr = map[netip.Addr]tailcfg.NodeID{}
	}
	// First pass, mark everything unwanted.
	for k := range nb.nodeByAddr {
		nb.nodeByAddr[k] = 0
	}
	addNode := func(n tailcfg.NodeView) {
		for _, ipp := range n.Addresses().All() {
			if ipp.IsSingleIP() {
				nb.nodeByAddr[ipp.Addr()] = n.ID()
			}
		}
	}
	if nm.SelfNode.Valid() {
		addNode(nm.SelfNode)
	}
	for _, p := range nm.Peers {
		addNode(p)
	}
	// Third pass, actually delete the unwanted items.
	for k, v := range nb.nodeByAddr {
		if v == 0 {
			delete(nb.nodeByAddr, k)
		}
	}
}

func (nb *nodeBackend) updatePeersLocked() {
	nm := nb.netMap
	if nm == nil {
		nb.peers = nil
		return
	}

	// First pass, mark everything unwanted.
	for k := range nb.peers {
		nb.peers[k] = tailcfg.NodeView{}
	}

	// Second pass, add everything wanted.
	for _, p := range nm.Peers {
		mak.Set(&nb.peers, p.ID(), p)
	}

	// Third pass, remove deleted things.
	for k, v := range nb.peers {
		if !v.Valid() {
			delete(nb.peers, k)
		}
	}
}

func (nb *nodeBackend) UpdateNetmapDelta(muts []netmap.NodeMutation) (handled bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if nb.netMap == nil || len(nb.peers) == 0 {
		return false
	}

	// Locally cloned mutable nodes, to avoid calling AsStruct (clone)
	// multiple times on a node if it's mutated multiple times in this
	// call (e.g. its endpoints + online status both change)
	var mutableNodes map[tailcfg.NodeID]*tailcfg.Node

	for _, m := range muts {
		n, ok := mutableNodes[m.NodeIDBeingMutated()]
		if !ok {
			nv, ok := nb.peers[m.NodeIDBeingMutated()]
			if !ok {
				// TODO(bradfitz): unexpected metric?
				return false
			}
			n = nv.AsStruct()
			mak.Set(&mutableNodes, nv.ID(), n)
		}
		m.Apply(n)
	}
	for nid, n := range mutableNodes {
		nb.peers[nid] = n.View()
	}
	return true
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

func (nb *nodeBackend) dnsConfigForNetmap(prefs ipn.PrefsView, selfExpired bool, logf logger.Logf, versionOS string) *dns.Config {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return dnsConfigForNetmap(nb.netMap, nb.peers, prefs, selfExpired, logf, versionOS)
}

func (nb *nodeBackend) exitNodeCanProxyDNS(exitNodeID tailcfg.StableNodeID) (dohURL string, ok bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return exitNodeCanProxyDNS(nb.netMap, nb.peers, exitNodeID)
}

// dnsConfigForNetmap returns a *dns.Config for the given netmap,
// prefs, client OS version, and cloud hosting environment.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func dnsConfigForNetmap(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, prefs ipn.PrefsView, selfExpired bool, logf logger.Logf, versionOS string) *dns.Config {
	if nm == nil {
		return nil
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
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
		Hosts:  map[dnsname.FQDN][]netip.Addr{},
	}

	// selfV6Only is whether we only have IPv6 addresses ourselves.
	selfV6Only := nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs6) &&
		!nm.GetAddresses().ContainsFunc(tsaddr.PrefixIs4)
	dcfg.OnlyIPv6 = selfV6Only

	wantAAAA := nm.AllCaps.Contains(tailcfg.NodeAttrMagicDNSPeerAAAA)

	// Populate MagicDNS records. We do this unconditionally so that
	// quad-100 can always respond to MagicDNS queries, even if the OS
	// isn't configured to make MagicDNS resolution truly
	// magic. Details in
	// https://github.com/tailscale/tailscale/issues/1886.
	set := func(name string, addrs views.Slice[netip.Prefix]) {
		if addrs.Len() == 0 || name == "" {
			return
		}
		fqdn, err := dnsname.ToFQDN(name)
		if err != nil {
			return // TODO: propagate error?
		}
		var have4 bool
		for _, addr := range addrs.All() {
			if addr.Addr().Is4() {
				have4 = true
				break
			}
		}
		var ips []netip.Addr
		for _, addr := range addrs.All() {
			if selfV6Only {
				if addr.Addr().Is6() {
					ips = append(ips, addr.Addr())
				}
				continue
			}
			// If this node has an IPv4 address, then
			// remove peers' IPv6 addresses for now, as we
			// don't guarantee that the peer node actually
			// can speak IPv6 correctly.
			//
			// https://github.com/tailscale/tailscale/issues/1152
			// tracks adding the right capability reporting to
			// enable AAAA in MagicDNS.
			if addr.Addr().Is6() && have4 && !wantAAAA {
				continue
			}
			ips = append(ips, addr.Addr())
		}
		dcfg.Hosts[fqdn] = ips
	}
	set(nm.Name, nm.GetAddresses())
	for _, peer := range peers {
		set(peer.Name(), peer.Addresses())
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
	}

	addDefault := func(resolvers []*dnstype.Resolver) {
		dcfg.DefaultResolvers = append(dcfg.DefaultResolvers, resolvers...)
	}

	// If we're using an exit node and that exit node is new enough (1.19.x+)
	// to run a DoH DNS proxy, then send all our DNS traffic through it.
	if dohURL, ok := exitNodeCanProxyDNS(nm, peers, prefs.ExitNodeID()); ok {
		addDefault([]*dnstype.Resolver{{Addr: dohURL}})
		return dcfg
	}

	// If the user has set default resolvers ("override local DNS"), prefer to
	// use those resolvers as the default, otherwise if there are WireGuard exit
	// node resolvers, use those as the default.
	if len(nm.DNS.Resolvers) > 0 {
		addDefault(nm.DNS.Resolvers)
	} else {
		if resolvers, ok := wireguardExitNodeDNSResolvers(nm, peers, prefs.ExitNodeID()); ok {
			addDefault(resolvers)
		}
	}

	for suffix, resolvers := range nm.DNS.Routes {
		fqdn, err := dnsname.ToFQDN(suffix)
		if err != nil {
			logf("[unexpected] non-FQDN route suffix %q", suffix)
		}

		// Create map entry even if len(resolvers) == 0; Issue 2706.
		// This lets the control plane send ExtraRecords for which we
		// can authoritatively answer "name not exists" for when the
		// control plane also sends this explicit but empty route
		// making it as something we handle.
		//
		// While we're already populating it, might as well size the
		// slice appropriately.
		// Per #9498 the exact requirements of nil vs empty slice remain
		// unclear, this is a haunted graveyard to be resolved.
		dcfg.Routes[fqdn] = make([]*dnstype.Resolver, 0, len(resolvers))
		dcfg.Routes[fqdn] = append(dcfg.Routes[fqdn], resolvers...)
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
