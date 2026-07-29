// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"net/netip"
	"testing"

	tsmetrics "tailscale.com/metrics"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

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
			sc := newSubnetCounters(new(usermetric.Registry))
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
	sc := newSubnetCounters(new(usermetric.Registry))
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
	reg := new(usermetric.Registry)
	sc := newSubnetCounters(reg)

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
	sc := newSubnetCounters(new(usermetric.Registry))
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

func BenchmarkSubnetCountersAdd(b *testing.B) {
	b.ReportAllocs()
	sc := newSubnetCounters(new(usermetric.Registry))
	sc.setRoutes([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.168.0.0/24"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("10.2.0.0/16"),
	})
	addr := netip.MustParseAddr("10.1.2.3")
	for range b.N {
		if rc := sc.forAddr(addr); rc != nil {
			rc.add(1500, false)
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
	sc := newSubnetCounters(new(usermetric.Registry))
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
