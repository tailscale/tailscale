// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"cmp"
	"expvar"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
)

// subnetRouteLabels are the Prometheus labels for the per-route subnet
// forwarding counters.
type subnetRouteLabels struct {
	// Route is the advertised route the traffic was attributed to,
	// e.g. "10.1.0.0/16".
	Route string `prom:"route"`
	// Direction is "tx" or "rx", from the subnet router's point of view.
	// See the metric help text for the exact meaning.
	Direction string `prom:"direction"`
}

const (
	directionTx = "tx"
	directionRx = "rx"

	bytesHelp = "Bytes forwarded on behalf of tailnet peers for each advertised subnet route. " +
		`Direction is from the subnet router's point of view: "tx" was sent into the subnet, ` +
		`"rx" was received from the subnet and returned to the peer.`
	packetsHelp = "Packets forwarded on behalf of tailnet peers for each advertised subnet route. " +
		`Direction is from the subnet router's point of view: "tx" was sent into the subnet, ` +
		`"rx" was received from the subnet and returned to the peer.`

	// maxRetainedRoutes caps how many routes' counters are kept alive for the
	// process's lifetime; see subnetCounters.counters for why retention is
	// needed and evictRetained for what happens past the cap.
	//
	// A subnet router's advertised set is admin-configured and small; the cap
	// only matters if it churns unexpectedly. 4 KiB of routeCounters is a few
	// hundred KiB, and at the cap the labeled series are still bounded by the
	// advertised set, not by this.
	maxRetainedRoutes = 4096
)

// Aggregate node-level clientmetrics, registered over the same [expvar.Int]
// values that back the labeled usermetrics. clientmetrics cannot express
// labels, so these are sums across every advertised route.
var (
	cMetricSubnetForwardedTxBytes   = clientmetric.NewAggregateCounter("subnet_forwarded_tx_bytes")
	cMetricSubnetForwardedRxBytes   = clientmetric.NewAggregateCounter("subnet_forwarded_rx_bytes")
	cMetricSubnetForwardedTxPackets = clientmetric.NewAggregateCounter("subnet_forwarded_tx_packets")
	cMetricSubnetForwardedRxPackets = clientmetric.NewAggregateCounter("subnet_forwarded_rx_packets")
)

// routeCounters holds the four counters for a single advertised route.
//
// The same [expvar.Int] values are referenced by the labeled usermetric maps
// and by the aggregate clientmetrics, so one atomic add on the packet path
// updates both metric systems.
type routeCounters struct {
	txBytes   expvar.Int
	rxBytes   expvar.Int
	txPackets expvar.Int
	rxPackets expvar.Int

	// lastActiveSeq is the value of subnetCounters.seq when this route was
	// last advertised. Eviction drops the least recently advertised routes
	// first. Only ever accessed from setRoutes.
	lastActiveSeq uint64
}

// add records a packet of size bytes in the given direction.
func (rc *routeCounters) add(bytes int, rx bool) {
	if rx {
		rc.rxBytes.Add(int64(bytes))
		rc.rxPackets.Add(1)
		return
	}
	rc.txBytes.Add(int64(bytes))
	rc.txPackets.Add(1)
}

// subnetCounters counts forwarded traffic per advertised subnet route.
//
// Routes are resolved to their [routeCounters] once, when the set of
// advertised routes changes, and the resulting pointers are stored as the
// prefix table's values. The packet path is then a single longest-prefix
// lookup plus atomic adds: no allocation, no label formatting, and no map
// hashing per packet.
//
// A subnetCounters lives for the lifetime of the [Wrapper] once created, even
// while the feature is disabled: the aggregate clientmetrics it registers
// values with cannot be unregistered individually, and both metric views are
// counters, which must never decrease. Disabling clears the lookup table
// instead, which is what the packet path checks.
//
// It is not safe to call setRoutes concurrently with itself; the engine calls
// it only from Reconfig. Lookups are safe concurrently with setRoutes.
type subnetCounters struct {
	bytesTotal   *usermetric.MultiLabelMap[subnetRouteLabels]
	packetsTotal *usermetric.MultiLabelMap[subnetRouteLabels]

	// table maps an address to the counters for the most specific advertised
	// route containing it. setRoutes swaps in a wholly new table rather than
	// mutating the published one, so the packet path needs no locking.
	//
	// It holds nil when no countable route is advertised, which is how the
	// packet path skips its work. It is owned by the [Wrapper] rather than
	// stored inline here so that the packet path reaches it with a single
	// atomic load, without first loading the subnetCounters: a node that has
	// not opted in must pay no more than one nil check per packet.
	table *atomicPrefixTable

	// counters holds the counters for every route advertised recently,
	// including withdrawn ones, up to maxRetainedRoutes entries.
	//
	// Withdrawn routes are retained because they must stay registered with the
	// aggregate clientmetrics: those are counters, and dropping a route's
	// contribution would make them decrease. Retaining the entry also means a
	// route that is withdrawn and later re-advertised resumes its previous
	// total instead of resetting. The labeled usermetric series *are* removed
	// on withdrawal, so per-route cardinality tracks the advertised set.
	//
	// Only ever accessed from setRoutes.
	counters map[netip.Prefix]*routeCounters

	// evicted accumulates the totals of routes dropped from counters once it
	// reached maxRetainedRoutes. It stays registered with the aggregates
	// forever, so eviction preserves their value; only the per-route breakdown
	// of those bytes is lost, and an evicted route has not been advertised for
	// at least maxRetainedRoutes reconfigs. Only ever accessed from setRoutes.
	evicted routeCounters

	// active is the set of currently advertised routes, i.e. those with live
	// labeled series. Only ever accessed from setRoutes.
	active map[netip.Prefix]bool

	// seq increments on every setRoutes call and orders routes by how recently
	// they were advertised, for eviction. Only ever accessed from setRoutes.
	seq uint64
}

// atomicPrefixTable is an atomically-swappable longest-prefix-match table.
type atomicPrefixTable struct {
	v atomic.Pointer[bart.Table[*routeCounters]]
}

func (a *atomicPrefixTable) load() *bart.Table[*routeCounters] { return a.v.Load() }
func (a *atomicPrefixTable) store(t *bart.Table[*routeCounters]) {
	a.v.Store(t)
}

// newSubnetCounters returns a subnetCounters that publishes its per-route
// series into reg and its lookup table into table. It starts with no routes,
// i.e. inactive.
func newSubnetCounters(reg *usermetric.Registry, table *atomicPrefixTable) *subnetCounters {
	sc := &subnetCounters{
		table:    table,
		counters: map[netip.Prefix]*routeCounters{},
		active:   map[netip.Prefix]bool{},
	}
	sc.registerAggregate(&sc.evicted)
	if buildfeatures.HasUserMetrics {
		sc.bytesTotal = usermetric.NewMultiLabelMapWithRegistry[subnetRouteLabels](
			reg, "tailscaled_subnet_forwarded_bytes_total", "counter", bytesHelp)
		sc.packetsTotal = usermetric.NewMultiLabelMapWithRegistry[subnetRouteLabels](
			reg, "tailscaled_subnet_forwarded_packets_total", "counter", packetsHelp)
	}
	return sc
}

// countableRoute reports whether a route should get its own counters.
//
// Exit routes are excluded: they are not subnet routes, and attributing all
// exit-node traffic to 0.0.0.0/0 would be misleading. This mirrors the
// Bits() > 0 check the network flow logger uses when classifying subnet
// traffic.
//
// 4via6 routes are excluded too, for M1. Their prefixes live inside
// fd7a:115c:a1e0::/48, so both endpoints of 4via6 traffic are Tailscale
// addresses and countSubnetRouteParsed's "exactly one Tailscale endpoint"
// test never admits such a packet. Admitting the route anyway would publish
// four series that can never move, which reads to an operator as an idle
// router rather than an unsupported route type. Counting 4via6 properly needs
// attribution on the translated v4 address, which is a later milestone.
func countableRoute(p netip.Prefix) bool {
	return p.IsValid() && p.Bits() > 0 && !tsaddr.IsViaPrefix(p)
}

// anyCountableRoute reports whether routes contains at least one route that
// would get counters, i.e. whether counting should be active at all.
func anyCountableRoute(routes []netip.Prefix) bool {
	for _, p := range routes {
		if countableRoute(p) {
			return true
		}
	}
	return false
}

// setRoutes updates the set of advertised routes being counted.
//
// Passing no countable routes deactivates counting without discarding any
// retained totals: the lookup table is cleared and the labeled series are
// removed, but the [expvar.Int] values stay registered with the aggregates so
// neither metric view decreases.
func (sc *subnetCounters) setRoutes(routes []netip.Prefix) {
	sc.seq++
	next := make(map[netip.Prefix]bool, len(routes))
	var tbl *bart.Table[*routeCounters]

	for _, p := range routes {
		if !countableRoute(p) {
			continue
		}
		p = p.Masked()
		if next[p] {
			continue
		}
		rc, ok := sc.counters[p]
		if !ok {
			rc = new(routeCounters)
			sc.counters[p] = rc
			sc.registerAggregate(rc)
		}
		rc.lastActiveSeq = sc.seq
		if !sc.active[p] {
			sc.setSeries(p, rc)
		}
		next[p] = true
		if tbl == nil {
			tbl = &bart.Table[*routeCounters]{}
		}
		tbl.Insert(p, rc)
	}

	// Remove the labeled series for routes that are no longer advertised.
	for p := range sc.active {
		if !next[p] {
			sc.deleteSeries(p)
		}
	}

	sc.active = next
	sc.evictRetained()
	sc.table.store(tbl)
}

// evictRetained drops the least recently advertised retained routes once
// counters exceeds maxRetainedRoutes, folding their totals into sc.evicted so
// that the aggregate clientmetrics keep their value.
//
// Currently advertised routes are never evicted: the cap is on retention of
// withdrawn routes, and the advertised set is bounded by admin configuration.
func (sc *subnetCounters) evictRetained() {
	if len(sc.counters) <= maxRetainedRoutes {
		return
	}
	// Evict down to half the cap so this runs amortized-rarely rather than on
	// every reconfig once at the cap.
	target := maxRetainedRoutes / 2
	type candidate struct {
		p   netip.Prefix
		seq uint64
	}
	cands := make([]candidate, 0, len(sc.counters))
	for p, rc := range sc.counters {
		if sc.active[p] {
			continue
		}
		cands = append(cands, candidate{p, rc.lastActiveSeq})
	}
	// Oldest first.
	slices.SortFunc(cands, func(a, b candidate) int { return cmp.Compare(a.seq, b.seq) })
	for _, c := range cands {
		if len(sc.counters) <= target {
			break
		}
		rc := sc.counters[c.p]
		// Fold the evicted totals into the residual counter, which stays
		// registered with the aggregates, then drop the entry. rc's own values
		// are still in the aggregates' registered set with no way to remove
		// them, so zero them out to avoid double counting: nothing references
		// rc after this, so no further adds can land on it.
		sc.evicted.txBytes.Add(rc.txBytes.Value())
		sc.evicted.rxBytes.Add(rc.rxBytes.Value())
		sc.evicted.txPackets.Add(rc.txPackets.Value())
		sc.evicted.rxPackets.Add(rc.rxPackets.Value())
		rc.txBytes.Set(0)
		rc.rxBytes.Set(0)
		rc.txPackets.Set(0)
		rc.rxPackets.Set(0)
		delete(sc.counters, c.p)
	}
}

// registerAggregate adds rc's counters to the node-level clientmetrics.
func (sc *subnetCounters) registerAggregate(rc *routeCounters) {
	if !buildfeatures.HasClientMetrics {
		return
	}
	cMetricSubnetForwardedTxBytes.Register(&rc.txBytes)
	cMetricSubnetForwardedRxBytes.Register(&rc.rxBytes)
	cMetricSubnetForwardedTxPackets.Register(&rc.txPackets)
	cMetricSubnetForwardedRxPackets.Register(&rc.rxPackets)
}

// setSeries publishes the labeled usermetric series for p.
func (sc *subnetCounters) setSeries(p netip.Prefix, rc *routeCounters) {
	if !buildfeatures.HasUserMetrics {
		return
	}
	route := p.String()
	sc.bytesTotal.Set(subnetRouteLabels{route, directionTx}, &rc.txBytes)
	sc.bytesTotal.Set(subnetRouteLabels{route, directionRx}, &rc.rxBytes)
	sc.packetsTotal.Set(subnetRouteLabels{route, directionTx}, &rc.txPackets)
	sc.packetsTotal.Set(subnetRouteLabels{route, directionRx}, &rc.rxPackets)
}

// deleteSeries removes the labeled usermetric series for a withdrawn route.
func (sc *subnetCounters) deleteSeries(p netip.Prefix) {
	if !buildfeatures.HasUserMetrics {
		return
	}
	route := p.String()
	sc.bytesTotal.Delete(subnetRouteLabels{route, directionTx})
	sc.bytesTotal.Delete(subnetRouteLabels{route, directionRx})
	sc.packetsTotal.Delete(subnetRouteLabels{route, directionTx})
	sc.packetsTotal.Delete(subnetRouteLabels{route, directionRx})
}

// forAddr returns the counters for the most specific advertised route
// containing addr, or nil if addr is not within any advertised route or
// counting is currently inactive.
func (sc *subnetCounters) forAddr(addr netip.Addr) *routeCounters {
	tbl := sc.table.load()
	if tbl == nil {
		return nil
	}
	rc, _ := tbl.Lookup(addr)
	return rc
}

// forRoute returns the counters registered for exactly p, or nil if p is not
// currently advertised.
func (sc *subnetCounters) forRoute(p netip.Prefix) *routeCounters {
	p = p.Masked()
	if !sc.active[p] {
		return nil
	}
	return sc.counters[p]
}

// retainedForRoute returns the counters retained for exactly p whether or not
// it is currently advertised, or nil if p has never been advertised (or was
// evicted). For tests.
func (sc *subnetCounters) retainedForRoute(p netip.Prefix) *routeCounters {
	return sc.counters[p.Masked()]
}

// aggregateTxBytesForTest returns the sum of tx bytes across every retained
// route plus the residual from evicted ones, i.e. what the aggregate
// clientmetric should read for this instance.
func (sc *subnetCounters) aggregateTxBytesForTest() int64 {
	total := sc.evicted.txBytes.Value()
	for _, rc := range sc.counters {
		total += rc.txBytes.Value()
	}
	return total
}
