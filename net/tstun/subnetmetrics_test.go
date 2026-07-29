// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"expvar"
	"fmt"
	"net/netip"
	"testing"

	tsmetrics "tailscale.com/metrics"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

// newTestSubnetCounters returns a standalone subnetCounters with its own
// registry and lookup table, for tests that don't need a whole Wrapper.
func newTestSubnetCounters() *subnetCounters {
	return newSubnetCounters(new(usermetric.Registry), new(atomicPrefixTable))
}

// routeCountsFor returns the four counter values for the given route, or
// zeroes if the route is not being counted.
func routeCountsFor(t *testing.T, sc *subnetCounters, route string) (txBytes, rxBytes, txPackets, rxPackets int64) {
	t.Helper()
	pfx := netip.MustParsePrefix(route)
	rc := sc.forRoute(pfx)
	if rc == nil {
		return 0, 0, 0, 0
	}
	return rc.txBytes.Value(), rc.rxBytes.Value(), rc.txPackets.Value(), rc.rxPackets.Value()
}

func TestSubnetCountersAttribution(t *testing.T) {
	tests := []struct {
		name string
		// routes advertised by this node.
		routes []string
		// remote is the non-Tailscale endpoint of the packet.
		remote string
		// wantRoute is the route the traffic should be attributed to,
		// or "" if the packet should not be counted at all.
		wantRoute string
	}{
		{
			name:      "within advertised prefix",
			routes:    []string{"10.1.0.0/16"},
			remote:    "10.1.2.3",
			wantRoute: "10.1.0.0/16",
		},
		{
			name:      "outside all prefixes is not counted",
			routes:    []string{"10.1.0.0/16"},
			remote:    "192.0.2.5",
			wantRoute: "",
		},
		{
			name:      "longest prefix wins",
			routes:    []string{"10.0.0.0/8", "10.1.0.0/16"},
			remote:    "10.1.2.3",
			wantRoute: "10.1.0.0/16",
		},
		{
			name:      "less specific route still matches outside the specific one",
			routes:    []string{"10.0.0.0/8", "10.1.0.0/16"},
			remote:    "10.9.9.9",
			wantRoute: "10.0.0.0/8",
		},
		{
			name:      "IPv4 exit route is excluded",
			routes:    []string{"0.0.0.0/0"},
			remote:    "192.0.2.5",
			wantRoute: "",
		},
		{
			name:      "IPv6 exit route is excluded",
			routes:    []string{"::/0"},
			remote:    "2001:db8::1",
			wantRoute: "",
		},
		{
			name:      "IPv6 subnet route",
			routes:    []string{"2001:db8::/32"},
			remote:    "2001:db8::1",
			wantRoute: "2001:db8::/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := newTestSubnetCounters()
			sc.setRoutes(mustPrefixes(t, tt.routes))

			remote := netip.MustParseAddr(tt.remote)
			got := sc.forAddr(remote)

			if tt.wantRoute == "" {
				if got != nil {
					t.Fatalf("forAddr(%v) = counters for a route; want no match", remote)
				}
				return
			}
			if got == nil {
				t.Fatalf("forAddr(%v) = no match; want counters for %v", remote, tt.wantRoute)
			}
			want := sc.forRoute(netip.MustParsePrefix(tt.wantRoute))
			if want == nil {
				t.Fatalf("route %v has no counters registered", tt.wantRoute)
			}
			if got != want {
				t.Errorf("forAddr(%v) attributed to the wrong route; want %v", remote, tt.wantRoute)
			}
		})
	}
}

func mustPrefixes(t *testing.T, ss []string) []netip.Prefix {
	t.Helper()
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}

func TestSubnetCountersDirections(t *testing.T) {
	sc := newTestSubnetCounters()
	sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16"}))

	// Two packets into the subnet, one back out of it.
	sc.forAddr(netip.MustParseAddr("10.1.2.3")).add(100, false)
	sc.forAddr(netip.MustParseAddr("10.1.2.4")).add(200, false)
	sc.forAddr(netip.MustParseAddr("10.1.2.3")).add(50, true)

	txBytes, rxBytes, txPackets, rxPackets := routeCountsFor(t, sc, "10.1.0.0/16")
	if txBytes != 300 {
		t.Errorf("txBytes = %d, want 300", txBytes)
	}
	if rxBytes != 50 {
		t.Errorf("rxBytes = %d, want 50", rxBytes)
	}
	if txPackets != 2 {
		t.Errorf("txPackets = %d, want 2", txPackets)
	}
	if rxPackets != 1 {
		t.Errorf("rxPackets = %d, want 1", rxPackets)
	}
}

func TestSubnetCountersRouteWithdrawal(t *testing.T) {
	sc := newTestSubnetCounters()

	sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16", "192.168.0.0/24"}))
	sc.forAddr(netip.MustParseAddr("10.1.2.3")).add(100, false)

	if got := seriesCount(sc); got != 8 {
		t.Fatalf("after advertising 2 routes, series count = %d, want 8", got)
	}

	// Withdraw one route; its series must go away, the other must remain.
	sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16"}))
	if got := seriesCount(sc); got != 4 {
		t.Errorf("after withdrawing 1 of 2 routes, series count = %d, want 4", got)
	}
	if sc.forRoute(netip.MustParsePrefix("192.168.0.0/24")) != nil {
		t.Error("withdrawn route still resolves via forRoute")
	}
	if sc.forAddr(netip.MustParseAddr("192.168.0.5")) != nil {
		t.Error("withdrawn route still matches in the lookup table")
	}

	// A re-advertised route resumes its previous total rather than resetting,
	// keeping the aggregate clientmetrics monotonic.
	sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16", "192.168.0.0/24"}))
	if txBytes, _, _, _ := routeCountsFor(t, sc, "10.1.0.0/16"); txBytes != 100 {
		t.Errorf("txBytes after re-advertise = %d, want 100 retained", txBytes)
	}

	// Churning the same route set repeatedly must not grow the series count.
	for range 20 {
		sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16"}))
		sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16", "192.168.0.0/24"}))
	}
	if got := seriesCount(sc); got != 8 {
		t.Errorf("after 20 churn cycles, series count = %d, want 8 (leak)", got)
	}
}

// seriesCount returns the number of labeled series currently published.
func seriesCount(sc *subnetCounters) int {
	var n int
	sc.bytesTotal.Do(func(tsmetrics.KeyValue[subnetRouteLabels]) { n++ })
	sc.packetsTotal.Do(func(tsmetrics.KeyValue[subnetRouteLabels]) { n++ })
	return n
}

// TestSubnetCountersNoAllocs pins the hot path to zero allocations. The naive
// implementation formats the prefix into a label value on every packet, which
// costs two allocations and roughly 4.7x the time; see the design doc.
func TestSubnetCountersNoAllocs(t *testing.T) {
	sc := newTestSubnetCounters()
	sc.setRoutes(mustPrefixes(t, []string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24"}))
	addr := netip.MustParseAddr("10.1.2.3")

	if got := testing.AllocsPerRun(1000, func() {
		if rc := sc.forAddr(addr); rc != nil {
			rc.add(1500, false)
		}
	}); got != 0 {
		t.Errorf("counting a packet allocated %v times per run, want 0", got)
	}
}

// TestSubnetCountersDisableEnableCycle checks that toggling the feature off and
// back on does not reset the labeled counters. Prometheus counters must never
// decrease: a reset produces a phantom rate() spike and false alerts.
//
// tailscale down/up, a profile switch, and Reconfig(&router.Config{}) from
// enterStateLocked all drive an empty route set through this path.
func TestSubnetCountersDisableEnableCycle(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	routes := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	tun.SetSubnetRoutes(routes)
	sc := tun.subnetCounters()
	if sc == nil {
		t.Fatal("counting disabled after SetSubnetRoutes")
	}
	sc.forAddr(netip.MustParseAddr("10.1.2.3")).add(1000000, false)

	// The labeled series and the aggregates must agree here, before the toggle.
	if got := labeledSeriesValue(t, sc, "10.1.0.0/16", directionTx, true); got != 1000000 {
		t.Fatalf("labeled tx_bytes before the toggle = %d, want 1000000", got)
	}

	// Disable, then re-enable with the same route.
	tun.SetSubnetRoutes(nil)
	tun.SetSubnetRoutes(routes)

	sc2 := tun.subnetCounters()
	if sc2 == nil {
		t.Fatal("counting disabled after re-enabling")
	}
	if got := labeledSeriesValue(t, sc2, "10.1.0.0/16", directionTx, true); got != 1000000 {
		t.Errorf("labeled tx_bytes after a disable/enable cycle = %d, want 1000000 retained "+
			"(a Prometheus counter must never decrease)", got)
	}
	if txBytes, _, _, _ := routeCountsFor(t, sc2, "10.1.0.0/16"); txBytes != 1000000 {
		t.Errorf("route tx_bytes after a disable/enable cycle = %d, want 1000000 retained", txBytes)
	}
}

// labeledSeriesValue returns the value published under the given labels, or -1
// if there is no such series.
func labeledSeriesValue(t *testing.T, sc *subnetCounters, route, direction string, bytes bool) int64 {
	t.Helper()
	m := sc.packetsTotal
	if bytes {
		m = sc.bytesTotal
	}
	got := int64(-1)
	m.Do(func(kv tsmetrics.KeyValue[subnetRouteLabels]) {
		if kv.Key.Route != route || kv.Key.Direction != direction {
			return
		}
		iv, ok := kv.Value.(*expvar.Int)
		if !ok {
			t.Fatalf("series %v/%v has value type %T, want *expvar.Int", route, direction, kv.Value)
		}
		got = iv.Value()
	})
	return got
}

// TestSubnetCountersDisabledCountsNothing checks that while the feature is
// disabled no traffic is counted, and that withdrawn routes' labeled series are
// removed even though their totals are retained.
func TestSubnetCountersDisabledCountsNothing(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	routes := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	tun.SetSubnetRoutes(routes)
	sc := tun.subnetCounters()
	pkt := udp4("100.64.0.1", "10.1.2.3", 123, 456)
	if _, err := tun.tdevWrite([][]byte{pkt}, 0); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}
	_, _, want, _ := routeCountsFor(t, sc, "10.1.0.0/16")
	if want != 1 {
		t.Fatalf("txPackets while enabled = %d, want 1", want)
	}

	tun.SetSubnetRoutes(nil)

	// Nothing is counted while disabled, and no series remain published.
	for range 5 {
		if _, err := tun.tdevWrite([][]byte{pkt}, 0); err != nil {
			t.Fatalf("tdevWrite: %v", err)
		}
	}
	if got := seriesCount(sc); got != 0 {
		t.Errorf("series count while disabled = %d, want 0", got)
	}
	// forRoute reports only advertised routes, so the withdrawn one is gone
	// from there; the retained totals must be untouched by the 5 packets.
	if got := sc.forRoute(netip.MustParsePrefix("10.1.0.0/16")); got != nil {
		t.Error("a withdrawn route still resolves via forRoute")
	}
	rc := sc.retainedForRoute(netip.MustParsePrefix("10.1.0.0/16"))
	if rc == nil {
		t.Fatal("the withdrawn route's counters were discarded, not retained")
	}
	if got := rc.txPackets.Value(); got != 1 {
		t.Errorf("retained txPackets after 5 packets while disabled = %d, want still 1", got)
	}
}

// TestSubnetCountersNoAggregateLeak checks that repeatedly enabling and
// disabling does not leak expvar values into the process-global aggregate
// clientmetrics. AggregateCounter has no unregister-one API and Value() is
// O(n) over the registered set, on every scrape and every logtail delta.
func TestSubnetCountersNoAggregateLeak(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	routes := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	tun.SetSubnetRoutes(routes)
	base := aggregateRegisteredCount()

	for range 10 {
		tun.SetSubnetRoutes(nil)
		tun.SetSubnetRoutes(routes)
	}
	if got := aggregateRegisteredCount() - base; got != 0 {
		t.Errorf("10 disable/enable cycles registered %d additional values with the "+
			"aggregate clientmetrics, want 0", got)
	}
}

// aggregateRegisteredCount returns how many expvar values are registered with
// the four aggregate clientmetrics.
func aggregateRegisteredCount() int {
	return cMetricSubnetForwardedTxBytes.RegisteredCountForTest() +
		cMetricSubnetForwardedRxBytes.RegisteredCountForTest() +
		cMetricSubnetForwardedTxPackets.RegisteredCountForTest() +
		cMetricSubnetForwardedRxPackets.RegisteredCountForTest()
}

// TestSubnetCountersRetentionBound checks that the retained-counter map is
// bounded. Retention is deliberate (a withdrawn route must keep contributing to
// the aggregates, which are counters) but unbounded retention lets an
// unexpectedly churning route set grow memory without limit.
func TestSubnetCountersRetentionBound(t *testing.T) {
	sc := newTestSubnetCounters()

	// Churn far more distinct routes than the cap, counting a byte on each so
	// that eviction has to preserve something.
	const n = maxRetainedRoutes * 3
	var wantTotal int64
	for i := range n {
		p := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		sc.setRoutes([]netip.Prefix{p})
		sc.forAddr(p.Addr().Next()).add(100, false)
		wantTotal += 100
	}

	if got := len(sc.counters); got > maxRetainedRoutes {
		t.Errorf("after %d single-route reconfigs, retained %d routeCounters, want at most %d",
			n, got, maxRetainedRoutes)
	}
	// Eviction must not lose counted bytes: the aggregate is a counter.
	if got := sc.aggregateTxBytesForTest(); got != wantTotal {
		t.Errorf("total tx bytes across retained plus evicted = %d, want %d "+
			"(eviction must not make the aggregate decrease)", got, wantTotal)
	}
}

// TestSubnetCountersExitNodeOnlyNotEnabled checks that a node advertising only
// exit routes does not install the counting hook: it would publish zero series
// while paying a decode and a lookup on every packet.
func TestSubnetCountersExitNodeOnlyNotEnabled(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSubnetRoutes([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	})
	if tun.SubnetRouteCountingEnabledForTest() {
		t.Error("counting is enabled for an exit-node-only route set; want disabled")
	}
}

// TestSubnetCountersViaRouteExcluded checks that 4via6 routes get no series.
// Both endpoints of 4via6 traffic are inside the Tailscale ULA range, so
// countSubnetRouteParsed can never attribute a packet to one, and publishing
// four permanently-zero series would read as "this route is idle".
func TestSubnetCountersViaRouteExcluded(t *testing.T) {
	sc := newTestSubnetCounters()
	// 4via6 form of 10.1.0.0/16 through site 7.
	via := netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:0/112")
	if !tsaddr.IsViaPrefix(via) {
		t.Fatalf("%v is not a via prefix; fix the test fixture", via)
	}
	sc.setRoutes([]netip.Prefix{via})
	if got := seriesCount(sc); got != 0 {
		t.Errorf("a 4via6 route published %d series, want 0 (they could never move)", got)
	}
	if sc.forAddr(via.Addr().Next()) != nil {
		t.Error("a 4via6 route is present in the lookup table")
	}
}

// TestWrapperSubnetRouteCountingOwnTraffic checks that traffic the node
// originates itself toward an address inside one of its own advertised prefixes
// is not counted. Only forwarded traffic belongs in these counters, and such a
// packet has exactly one Tailscale endpoint, so the endpoint test alone admits
// it -- with the direction inverted, since it is egress being counted as rx.
func TestWrapperSubnetRouteCountingOwnTraffic(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	const selfIP = "100.64.0.1"
	tun.SetSelfTailscaleAddrs(netip.MustParseAddr(selfIP), netip.Addr{})
	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	sc := tun.subnetCounters()
	if sc == nil {
		t.Fatal("counting disabled after SetSubnetRoutes")
	}

	// The node's own egress to a host inside its advertised prefix. This
	// leaves via the TUN read path, where forwarded return traffic is rx.
	go func() { chtun.Outbound <- udp4(selfIP, "10.1.2.3", 123, 456) }()

	var buf [MaxPacketSize]byte
	buffs := [][]byte{buf[:]}
	sizes := make([]int, 1)
	if _, err := tun.Read(buffs, sizes, 0); err != nil {
		t.Fatalf("Read: %v", err)
	}

	txBytes, rxBytes, txPackets, rxPackets := routeCountsFor(t, sc, "10.0.0.0/8")
	if rxPackets != 0 || rxBytes != 0 {
		t.Errorf("the node's own egress was counted as rx: rxBytes=%d rxPackets=%d; want 0, 0",
			rxBytes, rxPackets)
	}
	if txPackets != 0 || txBytes != 0 {
		t.Errorf("the node's own egress was counted as tx: txBytes=%d txPackets=%d; want 0, 0",
			txBytes, txPackets)
	}
}

// TestWrapperSubnetRouteCountingForwardedStillCounted is the companion to
// TestWrapperSubnetRouteCountingOwnTraffic: excluding the node's own traffic
// must not also exclude the forwarded traffic these counters exist for.
func TestWrapperSubnetRouteCountingForwardedStillCounted(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSelfTailscaleAddrs(netip.MustParseAddr("100.64.0.1"), netip.Addr{})
	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	sc := tun.subnetCounters()

	// Forwarded: from a subnet host, to a *peer*, not to this node.
	pkt := udp4("10.1.2.3", "100.64.0.2", 456, 123)
	go func() { chtun.Outbound <- pkt }()

	var buf [MaxPacketSize]byte
	buffs := [][]byte{buf[:]}
	sizes := make([]int, 1)
	if _, err := tun.Read(buffs, sizes, 0); err != nil {
		t.Fatalf("Read: %v", err)
	}

	_, rxBytes, _, rxPackets := routeCountsFor(t, sc, "10.0.0.0/8")
	if rxPackets != 1 || rxBytes != int64(len(pkt)) {
		t.Errorf("forwarded traffic: rxBytes=%d rxPackets=%d; want %d, 1", rxBytes, rxPackets, len(pkt))
	}
}

// TestWrapperSubnetRouteCountingStalePacket checks that the Read hook does not
// attribute traffic using addresses left over from a previous packet. Parsed is
// pool-reused across the loop and Decode does not clear Src/Dst when it bails
// out early, so a hook that reads them without an IPVersion check can count a
// stale address.
func TestWrapperSubnetRouteCountingStalePacket(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSelfTailscaleAddrs(netip.MustParseAddr("100.64.0.1"), netip.Addr{})
	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	sc := tun.subnetCounters()

	// A real forwarded packet, then a garbage one in the same batch. The
	// second must not be counted against the first's route.
	good := udp4("10.1.2.3", "100.64.0.2", 456, 123)
	junk := []byte{0x45, 0x74, 0x63, 0x70} // decodes as IPVersion 0
	go func() {
		chtun.Outbound <- good
		chtun.Outbound <- junk
	}()

	var bufs [2][MaxPacketSize]byte
	buffs := [][]byte{bufs[0][:], bufs[1][:]}
	sizes := make([]int, 2)
	for range 2 {
		if _, err := tun.Read(buffs, sizes, 0); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	_, rxBytes, _, rxPackets := routeCountsFor(t, sc, "10.0.0.0/8")
	if rxPackets != 1 || rxBytes != int64(len(good)) {
		t.Errorf("after one good and one undecodable packet: rxBytes=%d rxPackets=%d; want %d, 1",
			rxBytes, rxPackets, len(good))
	}
}

// TestSubnetCountersHotPathNoAllocs pins the real hooks, not just the
// forAddr+add pair, to zero allocations. A prefix.String() creeping back into
// countSubnetRouteParsed would allocate twice per packet.
func TestSubnetCountersHotPathNoAllocs(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSelfTailscaleAddrs(netip.MustParseAddr("100.64.0.1"), netip.Addr{})
	tun.SetSubnetRoutes(mustPrefixes(t, []string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24"}))

	pkt := udp4("100.64.0.2", "10.1.2.3", 123, 456)
	buf := make([]byte, PacketStartOffset+MaxPacketSize)
	copy(buf[PacketStartOffset:], pkt)

	// The tdevWrite/injectedRead hook, including its decode and the active
	// check the packet path actually runs.
	if got := testing.AllocsPerRun(1000, func() {
		if sc := tun.subnetCountersActive(); sc != nil {
			tun.countSubnetRoutePacket(sc, buf[PacketStartOffset:], false)
		}
	}); got != 0 {
		t.Errorf("countSubnetRoutePacket allocated %v times per run, want 0", got)
	}

	// And the Read hook, which counts an already-decoded packet.
	var p packet.Parsed
	p.Decode(buf[PacketStartOffset:])
	if got := testing.AllocsPerRun(1000, func() {
		if sc := tun.subnetCountersActive(); sc != nil {
			tun.countSubnetRouteParsed(sc, &p, true)
		}
	}); got != 0 {
		t.Errorf("countSubnetRouteParsed allocated %v times per run, want 0", got)
	}

	// The disabled path must be free too: nodes that have not opted in pay
	// only the nil check.
	tun.SetSubnetRoutes(nil)
	if got := testing.AllocsPerRun(1000, func() {
		if sc := tun.subnetCountersActive(); sc != nil {
			t.Fatal("counting is still active after SetSubnetRoutes(nil)")
		}
	}); got != 0 {
		t.Errorf("the disabled check allocated %v times per run, want 0", got)
	}
}

func BenchmarkSubnetCountersAdd(b *testing.B) {
	b.ReportAllocs()
	sc := newTestSubnetCounters()
	sc.setRoutes(benchRoutes)
	addr := netip.MustParseAddr("10.1.2.3")
	for range b.N {
		if rc := sc.forAddr(addr); rc != nil {
			rc.add(1500, false)
		}
	}
}

var benchRoutes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("10.1.0.0/16"),
	netip.MustParsePrefix("192.168.0.0/24"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("10.2.0.0/16"),
}

// BenchmarkSubnetCountersHook measures the whole per-packet hook as the write
// path runs it: the active check, the decode, the forwarded-traffic tests, the
// lookup, and the adds.
func BenchmarkSubnetCountersHook(b *testing.B) {
	b.ReportAllocs()
	bus := eventbustest.NewBus(b)
	_, tun := newFakeTUN(b.Logf, bus, false)
	defer tun.Close()

	tun.SetSelfTailscaleAddrs(netip.MustParseAddr("100.64.0.1"), netip.Addr{})
	tun.SetSubnetRoutes(benchRoutes)

	pkt := udp4("100.64.0.2", "10.1.2.3", 123, 456)
	buf := make([]byte, PacketStartOffset+MaxPacketSize)
	copy(buf[PacketStartOffset:], pkt)
	body := buf[PacketStartOffset:]

	for range b.N {
		if sc := tun.subnetCountersActive(); sc != nil {
			tun.countSubnetRoutePacket(sc, body, false)
		}
	}
}

// BenchmarkSubnetCountersHookDisabled measures what a node that has not opted
// in pays: the nil check and nothing else.
func BenchmarkSubnetCountersHookDisabled(b *testing.B) {
	b.ReportAllocs()
	bus := eventbustest.NewBus(b)
	_, tun := newFakeTUN(b.Logf, bus, false)
	defer tun.Close()

	pkt := udp4("100.64.0.2", "10.1.2.3", 123, 456)
	for range b.N {
		if sc := tun.subnetCountersActive(); sc != nil {
			tun.countSubnetRoutePacket(sc, pkt, false)
		}
	}
}

// TestWrapperSubnetRouteCountingTx checks that traffic entering the TUN from a
// tailnet peer, bound for a host inside an advertised subnet, is counted as tx:
// the router is sending it into the subnet on the peer's behalf.
func TestWrapperSubnetRouteCountingTx(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	if tun.subnetCounters() != nil {
		t.Fatal("counting is enabled before SetSubnetRoutes; want disabled by default")
	}
	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
	sc := tun.subnetCounters()
	if sc == nil {
		t.Fatal("counting still disabled after SetSubnetRoutes")
	}

	pkt := udp4("100.64.0.1", "10.1.2.3", 123, 456)
	if _, err := tun.tdevWrite([][]byte{pkt}, 0); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}

	txBytes, rxBytes, txPackets, rxPackets := routeCountsFor(t, sc, "10.1.0.0/16")
	if txPackets != 1 {
		t.Errorf("txPackets = %d, want 1", txPackets)
	}
	if txBytes != int64(len(pkt)) {
		t.Errorf("txBytes = %d, want %d", txBytes, len(pkt))
	}
	if rxPackets != 0 || rxBytes != 0 {
		t.Errorf("rx counters moved on a tx packet: rxBytes=%d rxPackets=%d", rxBytes, rxPackets)
	}

	// Traffic to an address outside every advertised route (exit node traffic)
	// must not be counted.
	if _, err := tun.tdevWrite([][]byte{udp4("100.64.0.1", "192.0.2.7", 1, 2)}, 0); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}
	if _, _, gotTx, _ := routeCountsFor(t, sc, "10.1.0.0/16"); gotTx != 1 {
		t.Errorf("txPackets = %d after an unrouted packet, want still 1", gotTx)
	}

	// Traffic between two tailnet addresses is the node's own, not forwarded.
	if _, err := tun.tdevWrite([][]byte{udp4("100.64.0.1", "100.64.0.2", 1, 2)}, 0); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}
	if _, _, gotTx, _ := routeCountsFor(t, sc, "10.1.0.0/16"); gotTx != 1 {
		t.Errorf("txPackets = %d after tailnet-only traffic, want still 1", gotTx)
	}
}

// TestWrapperSubnetRouteCountingBufferSlack checks that only the decoded
// packet length is counted, not the slack in the buffer holding it.
//
// wireguard-go hands Write a full-MTU buffer per packet with the payload at
// [PacketStartOffset:PacketStartOffset+n], so buffs[i][offset:] runs to the end
// of the buffer. Counting len(b) there would attribute every trailing byte of
// slack to the route and report a bogus mean packet size.
func TestWrapperSubnetRouteCountingBufferSlack(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
	sc := tun.subnetCounters()
	if sc == nil {
		t.Fatal("counting disabled after SetSubnetRoutes")
	}

	pkt := udp4("100.64.0.1", "10.1.2.3", 123, 456)
	buf := make([]byte, PacketStartOffset+MaxPacketSize)
	copy(buf[PacketStartOffset:], pkt)

	if _, err := tun.tdevWrite([][]byte{buf}, PacketStartOffset); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}

	txBytes, _, txPackets, _ := routeCountsFor(t, sc, "10.1.0.0/16")
	if txPackets != 1 {
		t.Errorf("txPackets = %d, want 1", txPackets)
	}
	if txBytes != int64(len(pkt)) {
		t.Errorf("txBytes = %d, want %d (the packet length, not the %d-byte buffer)",
			txBytes, len(pkt), len(buf)-PacketStartOffset)
	}
}

// TestWrapperSubnetRouteCountingRx checks that traffic read out of the TUN
// toward a tailnet peer is counted as rx: the router received it from the
// subnet and is returning it to the peer.
func TestWrapperSubnetRouteCountingRx(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	tun.SetSubnetRoutes([]netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
	sc := tun.subnetCounters()
	if sc == nil {
		t.Fatal("counting disabled after SetSubnetRoutes")
	}

	pkt := udp4("10.1.2.3", "100.64.0.1", 456, 123)
	go func() { chtun.Outbound <- pkt }()

	var buf [MaxPacketSize]byte
	buffs := [][]byte{buf[:]}
	sizes := make([]int, 1)
	if _, err := tun.Read(buffs, sizes, 0); err != nil {
		t.Fatalf("Read: %v", err)
	}

	txBytes, rxBytes, txPackets, rxPackets := routeCountsFor(t, sc, "10.1.0.0/16")
	if rxPackets != 1 {
		t.Errorf("rxPackets = %d, want 1", rxPackets)
	}
	if rxBytes != int64(len(pkt)) {
		t.Errorf("rxBytes = %d, want %d", rxBytes, len(pkt))
	}
	if txPackets != 0 || txBytes != 0 {
		t.Errorf("tx counters moved on an rx packet: txBytes=%d txPackets=%d", txBytes, txPackets)
	}
}

// TestWrapperSubnetRouteCountingOffByDefault verifies that traffic is not
// counted, and no series exist, until routes are set.
func TestWrapperSubnetRouteCountingOffByDefault(t *testing.T) {
	bus := eventbustest.NewBus(t)
	_, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	pkt := udp4("100.64.0.1", "10.1.2.3", 123, 456)
	if _, err := tun.tdevWrite([][]byte{pkt}, 0); err != nil {
		t.Fatalf("tdevWrite: %v", err)
	}
	if sc := tun.subnetCounters(); sc != nil {
		t.Errorf("subnetCounters is non-nil with no routes set: %v series", seriesCount(sc))
	}
}

// TestSubnetCountersAggregateAgreement checks that the unlabeled clientmetric
// aggregates move by the same amounts as the labeled series, since both are
// fed from the same backing values.
//
// The aggregates are process-global and other tests in this package register
// counters with them, so this compares deltas rather than absolute values.
func TestSubnetCountersAggregateAgreement(t *testing.T) {
	sc := newTestSubnetCounters()
	sc.setRoutes(mustPrefixes(t, []string{"10.1.0.0/16", "192.168.0.0/24"}))

	base := [4]int64{
		cMetricSubnetForwardedTxBytes.Value(),
		cMetricSubnetForwardedRxBytes.Value(),
		cMetricSubnetForwardedTxPackets.Value(),
		cMetricSubnetForwardedRxPackets.Value(),
	}

	sc.forAddr(netip.MustParseAddr("10.1.2.3")).add(1000, false)
	sc.forAddr(netip.MustParseAddr("10.1.2.4")).add(64, true)
	sc.forAddr(netip.MustParseAddr("192.168.0.9")).add(500, false)

	// Summing the per-route series gives what the aggregates should have
	// gained, because both read the same expvar.Int values.
	var want [4]int64
	for _, route := range []string{"10.1.0.0/16", "192.168.0.0/24"} {
		txB, rxB, txP, rxP := routeCountsFor(t, sc, route)
		want[0] += txB
		want[1] += rxB
		want[2] += txP
		want[3] += rxP
	}

	got := [4]int64{
		cMetricSubnetForwardedTxBytes.Value() - base[0],
		cMetricSubnetForwardedRxBytes.Value() - base[1],
		cMetricSubnetForwardedTxPackets.Value() - base[2],
		cMetricSubnetForwardedRxPackets.Value() - base[3],
	}
	names := [4]string{
		"subnet_forwarded_tx_bytes",
		"subnet_forwarded_rx_bytes",
		"subnet_forwarded_tx_packets",
		"subnet_forwarded_rx_packets",
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s gained %d, want %d (sum of the labeled series)", names[i], got[i], want[i])
		}
	}
}
