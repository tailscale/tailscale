// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routemanager tracks which peers own which IP prefixes and
// incrementally derives the routing data structures used by the rest
// of the system: a table mapping destination IP to the outbound peer,
// and the set of routes to program into the operating system's
// routing table.
//
// Updates are transactional: callers open a [Mutation] with
// [RouteManager.Begin], stage operations, and call [Mutation.Commit]
// to publish new snapshots. The published snapshots are immutable
// bart tables that share memory with their predecessors, so readers
// (notably the wireguard-go data plane) can hold and read them
// without locks. At most one [Mutation] may be active at a time,
// and the caller is responsible for synchronizing them.
package routemanager

import (
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// peerView is the subset of a peer's netmap state that affects
// routing. It is intentionally much narrower than tailcfg.NodeView so
// the RouteManager can be driven and tested without full netmap
// nodes; UpsertPeer converts from tailcfg.NodeView.
type peerView struct {
	// ID is the peer's node ID. It is the peer's identity within
	// the RouteManager.
	ID tailcfg.NodeID

	// Key is the peer's WireGuard public key. It is what gets
	// published into the data-path tables, so per-packet readers
	// need no NodeID-to-key translation.
	Key key.NodePublic

	// Jailed is whether the peer is restricted from initiating
	// connections to this node, in which case the data plane
	// applies its more restrictive jailed packet filter to the
	// peer's traffic.
	Jailed bool

	// MasqAddr4 and MasqAddr6 are the addresses the peer knows
	// this node as, per address family, if they differ from this
	// node's native addresses. The data plane masquerades (NATs)
	// traffic to and from the peer accordingly. An invalid address
	// means no masquerading for that family.
	MasqAddr4, MasqAddr6 netip.Addr

	// SelfAddrs are the peer's own addresses (its CGNAT IPv4 /32,
	// if any, and its Tailscale ULA IPv6 /128) plus any other
	// single Tailscale IPs it routes for, such as VIP service
	// addresses. They are routable regardless of Prefs.RouteAll.
	SelfAddrs []netip.Prefix

	// Routes are the peer's advertised routes: subnet routes and,
	// for exit-node candidates, the 0.0.0.0/0 and ::/0 exit routes.
	Routes []netip.Prefix
}

// PeerRoute is the payload of the outbound table: the attributes the
// data plane needs when handling a packet to or from one of the
// peer's prefixes. All prefixes contributed by a peer share a single
// interned *PeerRoute, and a new one is allocated whenever the
// attributes change, so published snapshots stay immutable and
// pointer identity doubles as a change check.
type PeerRoute struct {
	// Key is the peer's WireGuard public key.
	Key key.NodePublic

	// Jailed, MasqAddr4, and MasqAddr6 mirror the fields of the
	// same names in peerView.
	Jailed               bool
	MasqAddr4, MasqAddr6 netip.Addr
}

// routeAttrs returns the peer's attributes as published in the
// outbound table.
func (p peerView) routeAttrs() PeerRoute {
	return PeerRoute{
		Key:       p.Key,
		Jailed:    p.Jailed,
		MasqAddr4: p.MasqAddr4,
		MasqAddr6: p.MasqAddr6,
	}
}

// hasDataPlaneAttrs reports whether the peer has any attributes that
// require per-packet attention from the tun-layer data plane.
func (p peerView) hasDataPlaneAttrs() bool {
	return p.Jailed || p.MasqAddr4.IsValid() || p.MasqAddr6.IsValid()
}

// Prefs is the subset of ipn.Prefs that affects routing.
type Prefs struct {
	// ExitNodeID is the node ID of the peer selected as this
	// node's exit node, or zero if no exit node is selected or the
	// selected exit node does not resolve to a current peer.
	// (Callers resolve ipn.Prefs's stable node ID to a NodeID.)
	ExitNodeID tailcfg.NodeID

	// ExitNodeSelected is whether the prefs select any exit node at
	// all, even one that doesn't resolve to a current peer (in which
	// case ExitNodeID is zero). When set, the exit routes are always
	// in the OS route set: with a resolved exit node they carry its
	// traffic, and without one they blackhole internet traffic
	// rather than let it escape to the local network, per the
	// [tailscale.com/ipn.Prefs.ExitNodeID] docs. MDM's "auto:any"
	// placeholder relies on the blackhole while an exit node is
	// still being chosen.
	ExitNodeSelected bool

	// RouteAll is whether advertised subnet routes (non-exit
	// routes) from peers are accepted.
	RouteAll bool
}

// TailnetConfig is tailnet-global and environment-derived
// configuration that affects routing.
type TailnetConfig struct {
	// DisableIPv4 is whether the tailnet has disabled IPv4 self
	// addresses. If set, peers' IPv4 self addresses are ignored.
	DisableIPv4 bool

	// OneCGNAT is whether the OS route set should collapse peers'
	// CGNAT IPv4 self addresses into the single CGNAT /10 route
	// rather than per-peer /32s. The decision is made by the
	// caller (it depends on platform and interface state); the
	// RouteManager just applies it.
	OneCGNAT bool
}

// cgnatThreshold is the number of distinct CGNAT self-address routes
// above which the OS route set collapses them into the single CGNAT
// /10, even without TailnetConfig.OneCGNAT.
const cgnatThreshold = 10_000

// contribKind is a bit vector that describes how a peer contributes a
// prefix: as one of its own addresses, as an advertised route, or
// both.
type contribKind uint8

const (
	kindSelf contribKind = 1 << iota
	kindRoute

	// kindExtra marks a prefix from the extra allowed IPs set via
	// [Mutation.SetExtraAllowedIPs]. Extra prefixes appear in the
	// outbound table and in [RouteManager.PeerAllowedIPs], but
	// never in the OS route set.
	kindExtra
)

// scoreKey identifies a per-(node, prefix) score.
type scoreKey struct {
	id  tailcfg.NodeID
	pfx netip.Prefix
}

// RouteManager tracks peers' addresses and advertised routes and
// derives the routing snapshots.
//
// The snapshot accessors (Outbound, OSRoutes) may be called
// concurrently from any goroutine. Mutations must be serialized by
// the caller: Begin, then stage operations, then Commit (or Discard),
// before the next Begin. Commit panics if it detects overlapping
// mutations.
type RouteManager struct {
	logf  logger.Logf
	txGen atomic.Uint64

	outbound atomic.Pointer[bart.Table[*PeerRoute]]
	osRoutes atomic.Pointer[bart.Lite]

	// attrPeers counts the current peers with data-plane attributes
	// (jailed or masquerade addresses). It backs
	// [RouteManager.HasDataPlaneAttrs].
	attrPeers atomic.Int64

	// mu guards the working state below. Commit holds it while
	// applying staged operations and PeerAllowedIPs holds it while
	// reading, so reads cannot race a concurrent Commit. Mutations
	// are additionally serialized by callers (see Begin).
	mu sync.Mutex

	peers    map[tailcfg.NodeID]peerView
	routes   map[tailcfg.NodeID]*PeerRoute
	byPrefix map[netip.Prefix]map[tailcfg.NodeID]contribKind
	scores   map[scoreKey]int
	extras   map[tailcfg.NodeID][]netip.Prefix
	prefs    Prefs
	cfg      TailnetConfig

	// cgnatPfxs and ulaPfxs are the prefixes currently eligible
	// for the OS route set that are single CGNAT IPv4 addresses or
	// single Tailscale ULA IPv6 addresses, respectively. They feed
	// the coarse-route decisions.
	cgnatPfxs set.Set[netip.Prefix]
	ulaPfxs   set.Set[netip.Prefix]

	// coarseCGNAT is whether the OS route set currently contains
	// the single CGNAT /10 instead of per-peer /32s.
	coarseCGNAT bool
}

// New returns a new RouteManager with empty snapshots.
func New(logf logger.Logf) *RouteManager {
	if logf == nil {
		logf = logger.Discard
	}
	rm := &RouteManager{
		logf:      logf,
		peers:     make(map[tailcfg.NodeID]peerView),
		routes:    make(map[tailcfg.NodeID]*PeerRoute),
		byPrefix:  make(map[netip.Prefix]map[tailcfg.NodeID]contribKind),
		scores:    make(map[scoreKey]int),
		cgnatPfxs: make(set.Set[netip.Prefix]),
		ulaPfxs:   make(set.Set[netip.Prefix]),
	}
	rm.outbound.Store(&bart.Table[*PeerRoute]{})
	rm.osRoutes.Store(&bart.Lite{})
	return rm
}

// Outbound returns the current destination-IP-to-peer table. The
// returned table and the PeerRoutes it points to are immutable;
// callers must not modify them.
func (rm *RouteManager) Outbound() *bart.Table[*PeerRoute] {
	return rm.outbound.Load()
}

// OSRoutes returns the current set of prefixes to program into the
// OS routing table. The returned table is immutable; callers must not
// modify it.
func (rm *RouteManager) OSRoutes() *bart.Lite {
	return rm.osRoutes.Load()
}

// HasDataPlaneAttrs reports whether any current peer has data-plane
// attributes (jailed or masquerade addresses), that is, whether the
// tun-layer data plane needs the outbound table for per-packet NAT
// rewrites and jailed-filter selection. When it reports false, the
// data plane can skip those per-packet lookups entirely.
func (rm *RouteManager) HasDataPlaneAttrs() bool {
	return rm.attrPeers.Load() > 0
}

// PeerAllowedIPs returns the prefixes from which the given peer is
// currently allowed to originate traffic: its self addresses, its
// advertised subnet routes when Prefs.RouteAll is set, the exit
// routes when it is the selected exit node, and its extra allowed
// IPs (see [Mutation.SetExtraAllowedIPs]). It returns ok=false if
// the peer is unknown or currently contributes no prefixes; such a
// peer should not exist in the WireGuard device at all.
//
// The result is sorted, so identical routing state yields identical
// slices (letting callers cheaply detect no-op updates).
//
// Unlike the snapshot accessors, PeerAllowedIPs reads the working
// state. An internal mutex makes it safe to call concurrently with
// Commit.
func (rm *RouteManager) PeerAllowedIPs(id tailcfg.NodeID) (pfxs []netip.Prefix, ok bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.peerAllowedIPsLocked(id)
}

// peerAllowedIPsLocked implements [RouteManager.PeerAllowedIPs].
// rm.mu must be held.
func (rm *RouteManager) peerAllowedIPsLocked(id tailcfg.NodeID) (pfxs []netip.Prefix, ok bool) {
	p, ok := rm.peers[id]
	if !ok {
		return nil, false
	}
	for pfx, kind := range rm.contribs(p) {
		if rm.eligible(id, pfx, kind) {
			pfxs = append(pfxs, pfx)
		}
	}
	if len(pfxs) == 0 {
		return nil, false
	}
	tsaddr.SortPrefixes(pfxs)
	return pfxs, true
}

// Result describes what a Commit changed.
type Result struct {
	// PeersUpserted is the number of UpsertPeer operations applied.
	PeersUpserted int
	// PeersRemoved is the number of RemovePeer operations that
	// removed a known peer.
	PeersRemoved int
	// ScoresChanged is the number of SetScore operations that
	// changed a stored score.
	ScoresChanged int
	// ExtrasChanged is whether the commit changed the extra
	// allowed IPs.
	ExtrasChanged bool
	// PrefsChanged is whether the commit changed the prefs.
	PrefsChanged bool
	// TailnetCfgChanged is whether the commit changed the tailnet config.
	TailnetCfgChanged bool

	// OutboundChanged and OSRoutesChanged report whether each
	// output snapshot actually changed contents.
	OutboundChanged bool
	OSRoutesChanged bool

	// Outbound and OSRoutes are the fresh snapshot pointers, or
	// nil for any that didn't change.
	Outbound *bart.Table[*PeerRoute]
	OSRoutes *bart.Lite

	// AllowedIPs describes the peers whose allowed source prefixes
	// changed in this commit. The map is nil when no peer's allowed
	// prefixes changed.
	AllowedIPs PeersWithRouteChanges
}

// PeersWithRouteChanges maps the public key of each peer whose
// allowed source prefixes changed to its new sorted prefix list, as
// [RouteManager.PeerAllowedIPs] would now return it.
//
// A nil value means the peer no longer has any allowed prefixes,
// because it was removed or now contributes nothing; consumers
// should treat such peers as deleted. When a peer's key changes, the
// old key maps to nil and the new key to the peer's prefixes.
type PeersWithRouteChanges map[key.NodePublic][]netip.Prefix

type opKind uint8

const (
	opUpsert opKind = iota
	opRemove
	opPrefs
	opConfig
	opScore
	opExtras
)

type stagedOp struct {
	kind   opKind
	peer   peerView                          // for opUpsert
	id     tailcfg.NodeID                    // for opRemove, opScore
	pfx    netip.Prefix                      // for opScore
	score  int                               // for opScore
	prefs  Prefs                             // for opPrefs
	cfg    TailnetConfig                     // for opConfig
	extras map[tailcfg.NodeID][]netip.Prefix // for opExtras
}

// Mutation is an open transaction against a RouteManager. Operations
// are staged in order and applied atomically by Commit. A Mutation
// must not be used after Commit or Discard.
type Mutation struct {
	rm   *RouteManager
	gen  uint64
	done bool
	ops  []stagedOp
}

// Begin starts a mutation. Callers must serialize Begin/Commit pairs;
// overlapping mutations cause Commit to panic.
func (rm *RouteManager) Begin() *Mutation {
	return &Mutation{rm: rm, gen: rm.txGen.Load()}
}

func (m *Mutation) checkOpen() {
	if m.done {
		panic("routemanager: use of finished Mutation")
	}
}

// UpsertPeer stages an add or update of a peer. The peer's prefixes
// come solely from n.AllowedIPs: entries that are single Tailscale
// IPs (the peer's own addresses, or VIP service addresses it hosts)
// or that appear in n.Addresses count as self addresses and are
// always routable; the rest are treated as its advertised routes
// (subnet routes and, for exit-node candidates, the /0 exit routes).
func (m *Mutation) UpsertPeer(n tailcfg.NodeView) {
	m.upsertPeer(peerViewOf(n))
}

// peerViewOf reduces a tailcfg.NodeView to the routing-relevant
// peerView.
//
// Peers we cannot communicate with (expired, or predating both DERP
// and disco) contribute no prefixes. They remain tracked by ID and key
// so that a later update can make them routable again. AllowedIPs is
// the sole source of prefixes; an address absent from AllowedIPs is
// not routable. For the self-vs-route split,
// single Tailscale IPs are never subnets, so a VIP service address
// hosted by the peer lands in SelfAddrs and stays routable without
// Prefs.RouteAll.
func peerViewOf(n tailcfg.NodeView) peerView {
	pv := peerView{
		ID:        n.ID(),
		Key:       n.Key(),
		Jailed:    n.IsJailed(),
		MasqAddr4: n.SelfNodeV4MasqAddrForThisPeer().Get(),
		MasqAddr6: n.SelfNodeV6MasqAddrForThisPeer().Get(),
	}
	if n.Expired() {
		return pv
	}
	if n.DiscoKey().IsZero() && n.HomeDERP() == 0 && !n.IsWireGuardOnly() {
		return pv
	}
	for _, aip := range n.AllowedIPs().All() {
		isSelf := aip.IsSingleIP() && tsaddr.IsTailscaleIP(aip.Addr()) ||
			views.SliceContains(n.Addresses(), aip)
		if isSelf {
			pv.SelfAddrs = append(pv.SelfAddrs, aip)
		} else {
			pv.Routes = append(pv.Routes, aip)
		}
	}
	return pv
}

// upsertPeer stages an add or update of a peer from an
// already-reduced view.
func (m *Mutation) upsertPeer(p peerView) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opUpsert, peer: p})
}

// RemovePeer stages the removal of a peer.
func (m *Mutation) RemovePeer(id tailcfg.NodeID) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opRemove, id: id})
}

// SetPrefs stages a prefs update.
func (m *Mutation) SetPrefs(p Prefs) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opPrefs, prefs: p})
}

// SetTailnetConfig stages a tailnet config update.
func (m *Mutation) SetTailnetConfig(c TailnetConfig) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opConfig, cfg: c})
}

// SetScore stages a score update for the given peer and prefix.
// Scores are used to pick the outbound peer when multiple peers
// advertise the same prefix: highest score wins, with ties broken in
// a consistent manner. The default score is zero. Scores for a peer
// are dropped when the peer is removed.
//
// The plan is for feature/routecheck to do the route probing
// (reachability, latency, whatnot) and tweak the scores in some way,
// with details TBD. And as of 2026-07-10, the server never sends two
// nodes with the same AllowedIP CIDR anyway. But that will be
// changing and this code is preparing for that, letting the client
// make the decision about which of multiple peer candidates to use
// for a given route.
func (m *Mutation) SetScore(id tailcfg.NodeID, pfx netip.Prefix, score int) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opScore, id: id, pfx: normalizePrefix(pfx), score: score})
}

// SetExtraAllowedIPs stages a wholesale replacement of the extra
// allowed IPs: additional prefixes, keyed by node ID, that each peer
// may originate traffic from and that outbound traffic to should be
// sent to that peer. Extra prefixes appear in the outbound table and
// in [RouteManager.PeerAllowedIPs], but never in the OS route set.
// (In Tailscale they carry the conn25 extension's Transit IPs, which
// must reach WireGuard but not the OS routing table.)
//
// An entry for an unknown node ID is retained and takes effect if a
// peer with that ID is later upserted. Entries are dropped only by a
// later SetExtraAllowedIPs that omits them, not by peer removal.
//
// The caller must not mutate extras or its values after the call, and
// each prefix list must be in a stable order across calls so that
// unchanged entries are detected as no-ops.
func (m *Mutation) SetExtraAllowedIPs(extras map[tailcfg.NodeID][]netip.Prefix) {
	m.checkOpen()
	m.ops = append(m.ops, stagedOp{kind: opExtras, extras: extras})
}

// Discard abandons the mutation without applying any staged
// operations.
func (m *Mutation) Discard() {
	m.checkOpen()
	m.done = true
	m.ops = nil
}

// Commit applies the staged operations, publishes any changed
// snapshots, and reports what changed.
//
// Commit panics if this Mutation overlapped another Begin/Commit,
// which indicates a caller bug: callers are required to serialize
// mutations.
func (m *Mutation) Commit() Result {
	m.checkOpen()
	m.done = true
	rm := m.rm
	if !rm.txGen.CompareAndSwap(m.gen, m.gen+1) {
		panic("routemanager: concurrent Begin/Commit detected: caller must serialize mutations")
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(m.ops) == 0 {
		// Nothing was staged, so nothing can have changed; return
		// before allocating any of the diff-tracking state below.
		return Result{}
	}

	var res Result
	dirty := make(set.Set[netip.Prefix])
	fullRebuild := false

	// before records each affected peer's key and allowed prefixes
	// as of the start of the commit, so Result.AllowedIPs can be
	// computed by comparison afterwards. Each peer is snapshotted
	// the first time an op touches it (or on the first prefs or
	// config change, which can affect every peer), which is always
	// before any of its state has been mutated.
	type peerBefore struct {
		key     key.NodePublic
		pfxs    []netip.Prefix // nil if the peer had no allowed prefixes
		existed bool
	}
	var before map[tailcfg.NodeID]peerBefore
	snapshot := func(id tailcfg.NodeID) {
		if _, ok := before[id]; ok {
			return
		}
		var pb peerBefore
		if p, ok := rm.peers[id]; ok {
			pb.existed = true
			pb.key = p.Key
			pb.pfxs, _ = rm.peerAllowedIPsLocked(id)
		}
		mak.Set(&before, id, pb)
	}
	// TODO(bradfitz): snapshotting all peers on any prefs or tailnet
	// config change is a temporary lazy hack that makes those commits
	// O(all peers). Each such change only affects a knowable subset:
	// an exit node change affects only the old and new exit node, and
	// a RouteAll change affects only the peers currently contributing
	// non-self routes, which we could track incrementally. We
	// shouldn't need O(all peers) work here except once at startup.
	snapshotAll := func() {
		for id := range rm.peers {
			snapshot(id)
		}
	}

	for _, op := range m.ops {
		switch op.kind {
		case opUpsert:
			snapshot(op.peer.ID)
			rm.applyUpsert(op.peer, dirty)
			res.PeersUpserted++
		case opRemove:
			snapshot(op.id)
			if rm.applyRemove(op.id, dirty) {
				res.PeersRemoved++
			}
		case opPrefs:
			if rm.prefs != op.prefs {
				snapshotAll()
				rm.prefs = op.prefs
				res.PrefsChanged = true
				fullRebuild = true
			}
		case opConfig:
			if rm.cfg != op.cfg {
				snapshotAll()
				rm.cfg = op.cfg
				res.TailnetCfgChanged = true
				fullRebuild = true
			}
		case opScore:
			sk := scoreKey{op.id, op.pfx}
			old, had := rm.scores[sk]
			if op.score == 0 {
				if had {
					delete(rm.scores, sk)
					res.ScoresChanged++
					dirty.Add(op.pfx)
				}
			} else if !had || old != op.score {
				rm.scores[sk] = op.score
				res.ScoresChanged++
				dirty.Add(op.pfx)
			}
		case opExtras:
			for id := range rm.extras {
				snapshot(id)
			}
			for id := range op.extras {
				snapshot(id)
			}
			if rm.applyExtras(op.extras, dirty) {
				res.ExtrasChanged = true
			}
		}
	}

	if fullRebuild {
		rm.rebuildAll(&res)
	} else if len(dirty) > 0 {
		rm.applyDirty(dirty, &res)
	}

	// Diff each snapshotted peer's allowed prefixes against the
	// final working state to populate Result.AllowedIPs. Both
	// sides are sorted, so slices.Equal detects no-ops.
	for id, was := range before {
		now, _ := rm.peerAllowedIPsLocked(id)
		p, exists := rm.peers[id]
		switch {
		case !exists:
			if was.pfxs != nil {
				mak.Set(&res.AllowedIPs, was.key, nil) // nil signals deletion; see Result.AllowedIPs
			}
		case was.existed && was.key != p.Key:
			if was.pfxs != nil {
				mak.Set(&res.AllowedIPs, was.key, nil) // nil signals deletion; see Result.AllowedIPs
			}
			if now != nil {
				mak.Set(&res.AllowedIPs, p.Key, now)
			}
		default:
			if !slices.Equal(was.pfxs, now) {
				mak.Set(&res.AllowedIPs, p.Key, now)
			}
		}
	}
	return res
}

// normalizePrefix unmaps a 4-in-6 prefix address and masks off any
// non-address bits.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
}

// contribs returns the normalized per-prefix contributions of p,
// skipping (with a log message) any prefix that arrives with
// non-address bits set, mirroring the defensive check in
// ipnlocal.peerRoutes. It includes the peer's extra allowed IPs,
// except for peers that contribute no addresses or routes of their
// own (expired or otherwise non-communicable peers).
func (rm *RouteManager) contribs(p peerView) map[netip.Prefix]contribKind {
	c := make(map[netip.Prefix]contribKind, len(p.SelfAddrs)+len(p.Routes))
	add := func(pfx netip.Prefix, kind contribKind) {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits())
		if mm := pfx.Masked(); pfx != mm {
			rm.logf("routemanager: prefix %s from %s has non-address bits set; expected %s; skipping", pfx, p.Key.ShortString(), mm)
			return
		}
		c[pfx] |= kind
	}
	for _, pfx := range p.SelfAddrs {
		add(pfx, kindSelf)
	}
	for _, pfx := range p.Routes {
		add(pfx, kindRoute)
	}
	if len(c) > 0 {
		for _, pfx := range rm.extras[p.ID] {
			add(pfx, kindExtra)
		}
	}
	return c
}

// applyExtras replaces the extra allowed IPs with newExtras, updating
// working state and dirty for every peer whose extras changed. It
// reports whether anything changed.
func (rm *RouteManager) applyExtras(newExtras map[tailcfg.NodeID][]netip.Prefix, dirty set.Set[netip.Prefix]) (changed bool) {
	apply := func(id tailcfg.NodeID, pfxs []netip.Prefix) {
		if slices.Equal(rm.extras[id], pfxs) {
			return
		}
		changed = true
		p, exists := rm.peers[id]
		if !exists {
			rm.updateExtras(id, pfxs)
			return
		}
		oldC := rm.contribs(p)
		rm.updateExtras(id, pfxs)
		newC := rm.contribs(p)
		for pfx, kind := range oldC {
			if newC[pfx] != kind {
				rm.dropContrib(id, pfx)
				dirty.Add(pfx)
			}
		}
		for pfx, kind := range newC {
			if oldC[pfx] != kind {
				rm.addContrib(id, pfx, kind)
				dirty.Add(pfx)
			}
		}
	}
	for id := range rm.extras {
		if _, ok := newExtras[id]; !ok {
			apply(id, nil)
		}
	}
	for id, pfxs := range newExtras {
		apply(id, pfxs)
	}
	return changed
}

// updateExtras stores or deletes the extras entry for id.
func (rm *RouteManager) updateExtras(id tailcfg.NodeID, pfxs []netip.Prefix) {
	if len(pfxs) == 0 {
		delete(rm.extras, id)
	} else {
		mak.Set(&rm.extras, id, pfxs)
	}
}

// applyUpsert updates working state for an upserted peer, adding any
// affected prefixes to dirty.
func (rm *RouteManager) applyUpsert(p peerView, dirty set.Set[netip.Prefix]) {
	newC := rm.contribs(p)
	old, had := rm.peers[p.ID]
	attrsChanged := had && old.routeAttrs() != p.routeAttrs()
	if !had || attrsChanged {
		// Intern a fresh PeerRoute rather than mutating the old
		// one, which published snapshots may still reference.
		rm.routes[p.ID] = new(p.routeAttrs())
	}
	if had && old.hasDataPlaneAttrs() {
		rm.attrPeers.Add(-1)
	}
	if p.hasDataPlaneAttrs() {
		rm.attrPeers.Add(1)
	}
	if had {
		oldC := rm.contribs(old)
		for pfx, kind := range oldC {
			if newC[pfx] != kind {
				rm.dropContrib(p.ID, pfx)
				dirty.Add(pfx)
			} else if attrsChanged {
				dirty.Add(pfx)
			}
		}
		for pfx, kind := range newC {
			if oldC[pfx] != kind {
				rm.addContrib(p.ID, pfx, kind)
				dirty.Add(pfx)
			}
		}
	} else {
		for pfx, kind := range newC {
			rm.addContrib(p.ID, pfx, kind)
			dirty.Add(pfx)
		}
	}
	rm.peers[p.ID] = p
}

// applyRemove updates working state for a removed peer, adding its
// prefixes to dirty. It reports whether the peer was known.
func (rm *RouteManager) applyRemove(id tailcfg.NodeID, dirty set.Set[netip.Prefix]) bool {
	old, had := rm.peers[id]
	if !had {
		return false
	}
	for pfx := range rm.contribs(old) {
		rm.dropContrib(id, pfx)
		dirty.Add(pfx)
	}
	delete(rm.peers, id)
	delete(rm.routes, id)
	if old.hasDataPlaneAttrs() {
		rm.attrPeers.Add(-1)
	}
	for sk := range rm.scores {
		if sk.id == id {
			delete(rm.scores, sk)
		}
	}
	return true
}

func (rm *RouteManager) addContrib(id tailcfg.NodeID, pfx netip.Prefix, kind contribKind) {
	nodes := rm.byPrefix[pfx]
	if nodes == nil {
		nodes = make(map[tailcfg.NodeID]contribKind)
		rm.byPrefix[pfx] = nodes
	}
	nodes[id] = kind
}

func (rm *RouteManager) dropContrib(id tailcfg.NodeID, pfx netip.Prefix) {
	nodes := rm.byPrefix[pfx]
	delete(nodes, id)
	if len(nodes) == 0 {
		delete(rm.byPrefix, pfx)
	}
}

// eligible reports whether id's contribution of pfx (of the given
// kind) should be reflected in the outbound table and in the peer's
// allowed source prefixes, per current prefs and tailnet config.
// Extra allowed IPs are always eligible here, but are excluded from
// the OS route set by [RouteManager.desiredFor].
func (rm *RouteManager) eligible(id tailcfg.NodeID, pfx netip.Prefix, kind contribKind) bool {
	if kind&kindSelf != 0 {
		if !(pfx.Addr().Is4() && rm.cfg.DisableIPv4) {
			return true
		}
	}
	if kind&kindRoute != 0 {
		if tsaddr.IsExitRoute(pfx) {
			return rm.prefs.ExitNodeID != 0 && id == rm.prefs.ExitNodeID
		}
		return rm.prefs.RouteAll
	}
	return kind&kindExtra != 0
}

// desiredFor computes the desired output state for pfx from the
// current working state: the outbound winner (nil if the prefix has
// no outbound winner) and whether the prefix belongs in the OS route
// set.
func (rm *RouteManager) desiredFor(pfx netip.Prefix) (out *PeerRoute, os bool) {
	var bestID tailcfg.NodeID
	var bestScore int
	for id, kind := range rm.byPrefix[pfx] {
		if !rm.eligible(id, pfx, kind) {
			continue
		}
		if rm.eligible(id, pfx, kind&^kindExtra) {
			os = true
		}
		sc := rm.scores[scoreKey{id, pfx}]
		if out == nil || sc > bestScore || (sc == bestScore && id < bestID) {
			bestID, bestScore = id, sc
			out = rm.routes[id]
		}
	}
	return out, os
}

// osClass classifies a prefix for the OS route set.
type osClass uint8

const (
	osPlain osClass = iota // installed as-is when eligible
	osCGNAT                // single CGNAT IPv4 addr; subject to /10 coarsening
	osULA                  // single Tailscale ULA IPv6 addr; always coarsened
)

func classify(pfx netip.Prefix) osClass {
	if !pfx.IsSingleIP() {
		return osPlain
	}
	if pfx.Addr().Is4() && tsaddr.CGNATRange().Contains(pfx.Addr()) {
		return osCGNAT
	}
	if pfx.Addr().Is6() && tsaddr.TailscaleULARange().Contains(pfx.Addr()) {
		return osULA
	}
	return osPlain
}

func (rm *RouteManager) cgnatThreshold() int {
	if rm.cfg.OneCGNAT {
		return 1
	}
	return cgnatThreshold
}

// tableSet returns a table derived from t, in which pfx's presence
// matches want, reporting whether the result table differs from t.
func tableSet(t *bart.Lite, pfx netip.Prefix, want bool) (*bart.Lite, bool) {
	has := t.Get(pfx)
	if has == want {
		return t, false
	}
	if want {
		return t.InsertPersist(pfx), true
	}
	return t.DeletePersist(pfx), true
}

// applyDirty incrementally updates the output snapshots for the dirty
// prefixes and publishes any that changed.
func (rm *RouteManager) applyDirty(dirty set.Set[netip.Prefix], res *Result) {
	out := rm.outbound.Load()
	osr := rm.osRoutes.Load()
	var outChanged, osChanged bool

	var cgnatDirty []netip.Prefix
	for pfx := range dirty {
		want, wantOS := rm.desiredFor(pfx)
		if rm.prefs.ExitNodeSelected && tsaddr.IsExitRoute(pfx) {
			// The exit routes stay in the OS route set as long as an
			// exit node is selected, even with no eligible
			// contributor, to blackhole rather than leak internet
			// traffic. See [Prefs.ExitNodeSelected].
			wantOS = true
		}

		if cur, ok := out.Get(pfx); (want != nil) != ok || (ok && cur != want) {
			if want != nil {
				out = out.InsertPersist(pfx, want)
			} else {
				out = out.DeletePersist(pfx)
			}
			outChanged = true
		}

		switch classify(pfx) {
		case osULA:
			if wantOS {
				rm.ulaPfxs.Add(pfx)
			} else {
				rm.ulaPfxs.Delete(pfx)
			}
		case osCGNAT:
			if wantOS {
				rm.cgnatPfxs.Add(pfx)
			} else {
				rm.cgnatPfxs.Delete(pfx)
			}
			cgnatDirty = append(cgnatDirty, pfx)
		case osPlain:
			var ch bool
			osr, ch = tableSet(osr, pfx, wantOS)
			osChanged = osChanged || ch
		}
	}

	var ch bool
	osr, ch = tableSet(osr, tsaddr.TailscaleULARange(), len(rm.ulaPfxs) > 0)
	osChanged = osChanged || ch

	wantCoarse := len(rm.cgnatPfxs) > rm.cgnatThreshold()
	if wantCoarse != rm.coarseCGNAT {
		rm.coarseCGNAT = wantCoarse
		for pfx := range rm.cgnatPfxs {
			osr, ch = tableSet(osr, pfx, !wantCoarse)
			osChanged = osChanged || ch
		}
		osr, ch = tableSet(osr, tsaddr.CGNATRange(), wantCoarse)
		osChanged = osChanged || ch
	}
	for _, pfx := range cgnatDirty {
		osr, ch = tableSet(osr, pfx, !rm.coarseCGNAT && rm.cgnatPfxs.Contains(pfx))
		osChanged = osChanged || ch
	}

	rm.publish(out, outChanged, osr, osChanged, res)
}

// rebuildAll recomputes the output snapshots from scratch and
// publishes those that changed. It runs on prefs or tailnet config
// changes, where O(number of prefixes) work is acceptable.
func (rm *RouteManager) rebuildAll(res *Result) {
	out := &bart.Table[*PeerRoute]{}
	osr := &bart.Lite{}
	clear(rm.cgnatPfxs)
	clear(rm.ulaPfxs)

	var plain []netip.Prefix
	for pfx := range rm.byPrefix {
		want, wantOS := rm.desiredFor(pfx)
		if want == nil {
			continue
		}
		out.Insert(pfx, want)
		if !wantOS {
			continue
		}
		switch classify(pfx) {
		case osULA:
			rm.ulaPfxs.Add(pfx)
		case osCGNAT:
			rm.cgnatPfxs.Add(pfx)
		case osPlain:
			plain = append(plain, pfx)
		}
	}

	for _, pfx := range plain {
		osr.Insert(pfx)
	}
	if rm.prefs.ExitNodeSelected {
		// Blackhole (or carry) internet traffic while any exit node
		// is selected, resolved or not. See [Prefs.ExitNodeSelected].
		for _, pfx := range tsaddr.ExitRoutes() {
			osr.Insert(pfx)
		}
	}
	if len(rm.ulaPfxs) > 0 {
		osr.Insert(tsaddr.TailscaleULARange())
	}
	rm.coarseCGNAT = len(rm.cgnatPfxs) > rm.cgnatThreshold()
	if rm.coarseCGNAT {
		osr.Insert(tsaddr.CGNATRange())
	} else {
		for pfx := range rm.cgnatPfxs {
			osr.Insert(pfx)
		}
	}

	rm.publish(out, !out.Equal(rm.outbound.Load()),
		osr, !osr.Equal(rm.osRoutes.Load()), res)
}

// publish stores the changed snapshots and records them in res.
func (rm *RouteManager) publish(out *bart.Table[*PeerRoute], outChanged bool,
	osr *bart.Lite, osChanged bool, res *Result) {
	if outChanged {
		rm.outbound.Store(out)
		res.OutboundChanged = true
		res.Outbound = out
	}
	if osChanged {
		rm.osRoutes.Store(osr)
		res.OSRoutesChanged = true
		res.OSRoutes = osr
	}
}
