// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"go4.org/netipx"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/slicesx"
	"tailscale.com/wgengine/filter"
)

// localNodeContext holds the [LocalBackend]'s context tied to a local node (usually the current one).
//
// Its exported methods are safe for concurrent use, but the struct is not a snapshot of state at a given moment;
// its state can change between calls. For example, asking for the same value (e.g., netmap or prefs) twice
// may return different results. Returned values are immutable and safe for concurrent use.
//
// If both the [LocalBackend]'s internal mutex and the [localNodeContext] mutex must be held at the same time,
// the [LocalBackend] mutex must be acquired first. See the comment on the [LocalBackend] field for more details.
//
// Two pointers to different [localNodeContext] instances represent different local nodes.
// However, there's currently a bug where a new [localNodeContext] might not be created
// during an implicit node switch (see tailscale/corp#28014).

// In the future, we might want to include at least the following in this struct (in addition to the current fields).
// However, not everything should be exported or otherwise made available to the outside world (e.g. [ipnext] extensions,
// peer API handlers, etc.).
//   - [ipn.State]: when the LocalBackend switches to a different [localNodeContext], it can update the state of the old one.
//   - [ipn.LoginProfileView] and [ipn.Prefs]: we should update them when the [profileManager] reports changes to them.
//     In the future, [profileManager] (and the corresponding methods of the [LocalBackend]) can be made optional,
//     and something else could be used to set them once or update them as needed.
//   - [tailcfg.HostinfoView]: it includes certain fields that are tied to the current profile/node/prefs. We should also
//     update to build it once instead of mutating it in twelvety different places.
//   - [filter.Filter] (normal and jailed, along with the filterHash): the localNodeContext could have a method to (re-)build
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
type localNodeContext struct {
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
	// and must not escape the [localNodeContext].
	peers map[tailcfg.NodeID]tailcfg.NodeView

	// nodeByAddr maps nodes' own addresses (excluding subnet routes) to node IDs.
	// It is mutated in place (with mu held) and must not escape the [localNodeContext].
	nodeByAddr map[netip.Addr]tailcfg.NodeID
}

func newLocalNodeContext() *localNodeContext {
	cn := &localNodeContext{}
	// Default filter blocks everything and logs nothing.
	noneFilter := filter.NewAllowNone(logger.Discard, &netipx.IPSet{})
	cn.filterAtomic.Store(noneFilter)
	return cn
}

func (c *localNodeContext) Self() tailcfg.NodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netMap == nil {
		return tailcfg.NodeView{}
	}
	return c.netMap.SelfNode
}

func (c *localNodeContext) SelfUserID() tailcfg.UserID {
	self := c.Self()
	if !self.Valid() {
		return 0
	}
	return self.User()
}

// SelfHasCap reports whether the specified capability was granted to the self node in the most recent netmap.
func (c *localNodeContext) SelfHasCap(wantCap tailcfg.NodeCapability) bool {
	return c.SelfHasCapOr(wantCap, false)
}

// SelfHasCapOr is like [localNodeContext.SelfHasCap], but returns the specified default value
// if the netmap is not available yet.
func (c *localNodeContext) SelfHasCapOr(wantCap tailcfg.NodeCapability, def bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netMap == nil {
		return def
	}
	return c.netMap.AllCaps.Contains(wantCap)
}

func (c *localNodeContext) NetworkProfile() ipn.NetworkProfile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ipn.NetworkProfile{
		// These are ok to call with nil netMap.
		MagicDNSName: c.netMap.MagicDNSSuffix(),
		DomainName:   c.netMap.DomainName(),
	}
}

// TODO(nickkhyl): update it to return a [tailcfg.DERPMapView]?
func (c *localNodeContext) DERPMap() *tailcfg.DERPMap {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netMap == nil {
		return nil
	}
	return c.netMap.DERPMap
}

func (c *localNodeContext) NodeByAddr(ip netip.Addr) (_ tailcfg.NodeID, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	nid, ok := c.nodeByAddr[ip]
	return nid, ok
}

func (c *localNodeContext) NodeByKey(k key.NodePublic) (_ tailcfg.NodeID, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netMap == nil {
		return 0, false
	}
	if self := c.netMap.SelfNode; self.Valid() && self.Key() == k {
		return self.ID(), true
	}
	// TODO(bradfitz,nickkhyl): add nodeByKey like nodeByAddr instead of walking peers.
	for _, n := range c.peers {
		if n.Key() == k {
			return n.ID(), true
		}
	}
	return 0, false
}

func (c *localNodeContext) PeerByID(id tailcfg.NodeID) (_ tailcfg.NodeView, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.peers[id]
	return n, ok
}

func (c *localNodeContext) UserByID(id tailcfg.UserID) (_ tailcfg.UserProfileView, ok bool) {
	c.mu.Lock()
	nm := c.netMap
	c.mu.Unlock()
	if nm == nil {
		return tailcfg.UserProfileView{}, false
	}
	u, ok := nm.UserProfiles[id]
	return u, ok
}

// Peers returns all the current peers in an undefined order.
func (c *localNodeContext) Peers() []tailcfg.NodeView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slicesx.MapValues(c.peers)
}

// unlockedNodesPermitted reports whether any peer with theUnsignedPeerAPIOnly bool set true has any of its allowed IPs
// in the specified packet filter.
//
// TODO(nickkhyl): It is here temporarily until we can move the whole [LocalBackend.updateFilterLocked] here,
// but change it so it builds and returns a filter for the current netmap/prefs instead of re-configuring the engine filter.
// Something like (*localNodeContext).RebuildFilters() (filter, jailedFilter *filter.Filter, changed bool) perhaps?
func (c *localNodeContext) unlockedNodesPermitted(packetFilter []filter.Match) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return packetFilterPermitsUnlockedNodes(c.peers, packetFilter)
}

func (c *localNodeContext) filter() *filter.Filter {
	return c.filterAtomic.Load()
}
