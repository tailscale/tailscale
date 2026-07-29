// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"expvar"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"tailscale.com/feature/buildfeatures"
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
// It is not safe to call setRoutes concurrently with itself; the engine calls
// it only from Reconfig. Lookups are safe concurrently with setRoutes.
type subnetCounters struct {
	bytesTotal   *usermetric.MultiLabelMap[subnetRouteLabels]
	packetsTotal *usermetric.MultiLabelMap[subnetRouteLabels]

	// table maps an address to the counters for the most specific advertised
	// route containing it. setRoutes swaps in a wholly new table rather than
	// mutating the published one, so the packet path needs no locking.
	table atomicPrefixTable

	// counters holds the counters for every route advertised during this
	// process's lifetime, including withdrawn ones.
	//
	// Entries are never removed. Withdrawn routes must stay registered with
	// the aggregate clientmetrics, because those are counters and dropping a
	// route's contribution would make them decrease. Retaining the entry also
	// means a route that is withdrawn and later re-advertised resumes its
	// previous total instead of resetting. The labeled usermetric series *are*
	// removed on withdrawal, so per-route cardinality tracks the advertised
	// set. Only ever accessed from setRoutes.
	counters map[netip.Prefix]*routeCounters

	// active is the set of currently advertised routes, i.e. those with live
	// labeled series. Only ever accessed from setRoutes.
	active map[netip.Prefix]bool
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
// series into reg.
func newSubnetCounters(reg *usermetric.Registry) *subnetCounters {
	sc := &subnetCounters{
		counters: map[netip.Prefix]*routeCounters{},
		active:   map[netip.Prefix]bool{},
	}
	sc.table.store(&bart.Table[*routeCounters]{})
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
func countableRoute(p netip.Prefix) bool { return p.IsValid() && p.Bits() > 0 }

// setRoutes updates the set of advertised routes being counted.
func (sc *subnetCounters) setRoutes(routes []netip.Prefix) {
	next := make(map[netip.Prefix]bool, len(routes))
	tbl := &bart.Table[*routeCounters]{}

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
		if !sc.active[p] {
			sc.setSeries(p, rc)
		}
		next[p] = true
		tbl.Insert(p, rc)
	}

	// Remove the labeled series for routes that are no longer advertised.
	for p := range sc.active {
		if !next[p] {
			sc.deleteSeries(p)
		}
	}

	sc.active = next
	sc.table.store(tbl)
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
// containing addr, or nil if addr is not within any advertised route.
func (sc *subnetCounters) forAddr(addr netip.Addr) *routeCounters {
	rc, _ := sc.table.load().Lookup(addr)
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
