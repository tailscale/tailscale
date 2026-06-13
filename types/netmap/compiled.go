package netmap

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"weak"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter/filtertype"
)

// Compiled is a "compiled" state of a network map, using an internal
// representation that allows update of individual elements in constant time.
type Compiled struct {
	selfNodeID tailcfg.NodeID // index into idToNode

	// All the nodes of which this netmap is aware, including self and all peers.
	idToNode map[tailcfg.NodeID]tailcfg.NodeView

	// All the user profiles of which this netmap is aware.
	profiles map[tailcfg.UserID]tailcfg.UserProfileView

	// Lookup tables. Once initialized, these are kept up-to-date automatically.
	keyToID  map[key.NodePublic]tailcfg.NodeID // lazily initialized (NodeByKey)
	addrToID map[netip.Addr]tailcfg.NodeID     // lazily initialized (NodeByAddr)

	// The complete sorted slice of peers, computed on-demand but held weakly so
	// it will go away if it's not used anywhere else. Set to nil to explicitly
	// invalidate the cache.
	sortedPeers weak.Pointer[[]tailcfg.NodeView]

	// Other top-level fields of the initial network map.
	isCached   bool
	machineKey key.MachinePublic
	dnsConfig  tailcfg.DNSConfig
	pfMatch    []filtertype.Match
	pfRules    views.Slice[tailcfg.FilterRule]
	sshPolicy  *tailcfg.SSHPolicy // or nil
	derpMap    *tailcfg.DERPMap
	messages   map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage

	collectServices bool
	tkaEnabled      bool
	tkaHead         tka.AUMHash
	domain          string
	auditLogID      string

	// Notes:
	//  - AllCaps and NodeKey can be recovered from self.

	// To do: Lookup by ID (done), IP (done), key (done).
	// Ensure it stays in sync with the base map type.
	// Round-trip tests, if we think this is worth having.
	// Make sure it covers the existing use cases in nodeBackend, LocalBackend
	// maybe also magicsock?
	//
	// Omitted synchronization, but we could include a lock and then it could be
	// shared by address. Probably not safe given existing practice.
	//
	// Check profile handling. It looks like maybe we never delete profiles from
	// a netmap in the normal course, is that right?
	// The profile manager cleans up duplicates, but otherwise it appears we can
	// only delete a profile out-of-band maybe?
	// For now it just follows what nodeBackend does.
}

// Postcondition: takes ownership of the references in nm.
func Compile(nm *NetworkMap) *Compiled { return new(Compiled).initialize(nm) }

func (c *Compiled) initialize(nm *NetworkMap) *Compiled {
	*c = Compiled{
		isCached:   nm.Cached,
		machineKey: nm.MachineKey,
		dnsConfig:  nm.DNS,
		pfMatch:    nm.PacketFilter,
		pfRules:    nm.PacketFilterRules,
		sshPolicy:  nm.SSHPolicy,
		derpMap:    nm.DERPMap,
		messages:   nm.DisplayMessages,

		collectServices: nm.CollectServices,
		tkaEnabled:      nm.TKAEnabled,
		tkaHead:         nm.TKAHead,
		domain:          nm.Domain,
		auditLogID:      nm.DomainAuditLogID,

		// Lookup tables.
		idToNode: make(map[tailcfg.NodeID]tailcfg.NodeView),
		profiles: maps.Clone(nm.UserProfiles),
	}
	if s := nm.SelfNode; s.Valid() {
		c.idToNode[s.ID()] = s
		c.selfNodeID = s.ID()
	}
	for _, peer := range nm.Peers {
		id := peer.ID()
		c.idToNode[id] = peer
	}
	return c
}

// FullNetworkMap returns a new [NetworkMap] equivalent to c.
func (c *Compiled) FullNetworkMap() *NetworkMap {
	m := c.NetworkMapNoPeers()
	m.Peers = c.Peers()
	return m
}

// NetworkMapNoPeers returns a new [NetworkMap] equivalent to c, except that
// the Peers field is not populated.
func (c *Compiled) NetworkMapNoPeers() *NetworkMap {
	self := c.SelfNode()
	var selfKey key.NodePublic
	var allCaps set.Set[tailcfg.NodeCapability]
	if self.Valid() {
		selfKey = self.Key()
		allCaps = set.Of[tailcfg.NodeCapability]()
		for _, cap := range self.Capabilities().All() {
			allCaps.Add(cap)
		}
		for cap, _ := range self.CapMap().All() {
			allCaps.Add(cap)
		}
	}
	return &NetworkMap{
		Cached:            c.isCached,
		SelfNode:          self,
		AllCaps:           allCaps,
		NodeKey:           selfKey,
		MachineKey:        c.machineKey,
		Peers:             nil, // specifically not populated here; see NetworkMap
		DNS:               c.dnsConfig,
		PacketFilter:      c.pfMatch,
		PacketFilterRules: c.pfRules,
		SSHPolicy:         c.sshPolicy, // maybe clone?
		CollectServices:   c.collectServices,
		DERPMap:           c.derpMap, // maybe clone?
		DisplayMessages:   c.messages,
		TKAEnabled:        c.tkaEnabled,
		TKAHead:           c.tkaHead,
		Domain:            c.domain,
		DomainAuditLogID:  c.auditLogID,
		UserProfiles:      c.profiles,
	}
}

// SelfNode returns a view of the self node of c, or an invalid view.
func (c *Compiled) SelfNode() tailcfg.NodeView { return c.idToNode[c.selfNodeID] }

// Peers returns a slice of all the peers of c, ordered by [tailcfg.NodeID].
func (c *Compiled) Peers() []tailcfg.NodeView {
	p := c.sortedPeers.Value()
	if p == nil {
		sp := make([]tailcfg.NodeView, 0, len(c.idToNode))
		for id, nv := range c.idToNode {
			if id != c.selfNodeID {
				sp = append(sp, nv)
			}
		}
		slices.SortFunc(sp, func(a, b tailcfg.NodeView) int {
			return cmp.Compare(a.ID(), b.ID())
		})
		p = &sp
		c.sortedPeers = weak.Make(p)
	}
	return *p
}

// UpdateFull replaces the contents of c with the specified full network map.
func (c *Compiled) UpdateFull(nm *NetworkMap) { c.initialize(nm) }

// ApplyMutations updates the contents of c by applying the specified mutations.
func (c *Compiled) ApplyMutations(muts []NodeMutation) MutationResult {
	var result MutationResult
	for _, mut := range muts {
		id := mut.NodeIDBeingMutated()
		switch m := mut.(type) {
		case NodeMutationUpsert:
			c.updateNode(m.Node)
			if id == c.selfNodeID {
				result.SelfChanged = true
			} else {
				mak.Set(&result.PeersChanged, id, struct{}{})
			}
		case NodeMutationRemove:
			if c.removeNode(id) {
				mak.Set(&result.PeersRemoved, id, struct{}{})
			}
		default:
			if nv, ok := c.idToNode[id]; ok {
				n := nv.AsStruct()
				m.Apply(n)
				c.updateNode(n.View())
				if id == c.selfNodeID {
					result.SelfChanged = true
				} else {
					mak.Set(&result.PeersChanged, id, struct{}{})
				}
			}
		}
	}
	if result.DidPeersChange() {
		c.sortedPeers = weak.Make[[]tailcfg.NodeView](nil) // invalidate
	}
	return result
}

// UpdateProfiles adds and/or updates the profiles in c with the given profiles.
func (c *Compiled) UpdateProfiles(profiles map[tailcfg.UserID]tailcfg.UserProfileView) {
	if c.profiles == nil {
		c.profiles = maps.Clone(profiles)
		return
	}
	for id, pv := range profiles {
		c.profiles[id] = pv
	}
}

// NodeByID reports whether c has a node with the specified ID, and if so
// returns its view.
func (c *Compiled) NodeByID(id tailcfg.NodeID) (tailcfg.NodeView, bool) {
	nv, ok := c.idToNode[id]
	return nv, ok
}

// NodeByKey reports whether c has a node with the specified key, and if so
// returns its view.
func (c *Compiled) NodeByKey(nk key.NodePublic) (tailcfg.NodeView, bool) {
	if c.keyToID == nil { // strictly nil, not merely empty
		c.keyToID = make(map[key.NodePublic]tailcfg.NodeID)
		for id, nv := range c.idToNode {
			c.keyToID[nv.Key()] = id
		}
	}
	id, ok := c.keyToID[nk]
	if ok {
		nv, ok := c.idToNode[id]
		return nv, ok
	}
	return tailcfg.NodeView{}, false
}

// NodeByAddr reports whether c has a node with the specified address, and if
// so returns its view.
func (c *Compiled) NodeByAddr(addr netip.Addr) (tailcfg.NodeView, bool) {
	if c.addrToID == nil { // strictly nil, not merely empty
		c.addrToID = make(map[netip.Addr]tailcfg.NodeID)
		for _, nv := range c.idToNode {
			c.recordAddrs(nv)
		}
	}
	id, ok := c.addrToID[addr]
	if ok {
		nv, ok := c.idToNode[id]
		return nv, ok
	}
	return tailcfg.NodeView{}, false
}

// ProfileByID reports whether c has a profile with the specified ID, and if so
// returns its view.
func (c *Compiled) ProfileByID(id tailcfg.UserID) (tailcfg.UserProfileView, bool) {
	up, ok := c.profiles[id]
	return up, ok
}

// DERPMap returns the DERP map recorded by c, or nil if there is none.
func (c *Compiled) DERPMap() *tailcfg.DERPMap { return c.derpMap }

// MagicDNSSuffix returns the domains MagicDNS suffix.
func (c *Compiled) MagicDNSSuffix() string {
	if nv, ok := c.idToNode[c.selfNodeID]; ok {
		return MagicDNSSuffixOfNodeName(nv.Name())
	}
	return ""
}

// updateNode updates the specified node in the map.
// If the key and/or address lookup tables are initialized, it also updates those.
func (c *Compiled) updateNode(nv tailcfg.NodeView) {
	id := nv.ID()

	// Remove the old values from the lookup tables, if they are present.
	if old, ok := c.idToNode[id]; ok {
		delete(c.keyToID, old.Key())
		c.removeAddrs(old)
	}
	c.idToNode[nv.ID()] = nv
	if c.keyToID != nil {
		c.keyToID[nv.Key()] = nv.ID()
	}
	c.recordAddrs(nv)
}

// removeNode discards the specified node ID from the map.
// It also updates the key and address lookup tables, if they are initialized.
func (c *Compiled) removeNode(id tailcfg.NodeID) bool {
	nv, ok := c.idToNode[id]
	if !ok {
		return false
	}
	delete(c.idToNode, id)
	delete(c.keyToID, nv.Key())
	c.removeAddrs(nv)
	return true
}

// recordAddrs updates the address lookup table for nv.
// It is a no-op if the lookup table is not initialized.
func (c *Compiled) recordAddrs(nv tailcfg.NodeView) {
	if c.addrToID == nil {
		return
	}
	for _, ipp := range nv.Addresses().All() {
		if ipp.IsSingleIP() {
			c.addrToID[ipp.Addr()] = nv.ID()
		}
	}
}

// removeAddrs discards the addresses of nv from the address lookup table.
// It is a no-op if the lookup table is not initialized.
func (c *Compiled) removeAddrs(nv tailcfg.NodeView) {
	if c.addrToID == nil {
		return
	}
	for _, ipp := range nv.Addresses().All() {
		if ipp.IsSingleIP() {
			delete(c.addrToID, ipp.Addr())
		}
	}
}

// MutationResult summarizes the results of applying mutations to a [Compiled]
// network map.
type MutationResult struct {
	SelfChanged  bool
	PeersChanged set.Set[tailcfg.NodeID]
	PeersRemoved set.Set[tailcfg.NodeID]
}

// DidPeersChange reports whether m reflects any changes to the set of peers,
// either by additions, update, or removal.
func (m MutationResult) DidPeersChange() bool {
	return len(m.PeersChanged) != 0 || len(m.PeersRemoved) != 0
}
