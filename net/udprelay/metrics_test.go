// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"net/netip"
	"slices"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/util/usermetric"
)

func resetClientMetrics() {
	// clientmetrics are global and must be reset between test cases
	// for the assertMetricsMatch to work.
	metricForwarded44Packets.Set(0)
	metricForwarded46Packets.Set(0)
	metricForwarded64Packets.Set(0)
	metricForwarded66Packets.Set(0)
	metricForwarded44Bytes.Set(0)
	metricForwarded46Bytes.Set(0)
	metricForwarded64Bytes.Set(0)
	metricForwarded66Bytes.Set(0)
	metricEndpoints.Set(0)
}

func assertMetricsMatch(t *testing.T, s *Server) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	c := qt.New(t)
	var (
		ps44, ps46, ps64, ps66 uint64
		bs44, bs46, bs64, bs66 uint64

		es = len(s.serverEndpointByDisco)
	)
	for _, e := range s.serverEndpointByDisco {
		cs := e.extractClientInfo()
		a, b := cs[0], cs[1]
		a4, b4 := a.Endpoint.Addr().Is4(), b.Endpoint.Addr().Is4()
		if a4 && b4 {
			ps44 += b.PacketsTx
			ps44 += a.PacketsTx
			bs44 += b.BytesTx
			bs44 += a.BytesTx
		} else if a4 && !b4 {
			ps46 += b.PacketsTx
			ps64 += a.PacketsTx
			bs46 += b.BytesTx
			bs64 += a.BytesTx
		} else if !a4 && b4 {
			ps64 += b.PacketsTx
			ps46 += a.PacketsTx
			bs64 += b.BytesTx
			bs46 += a.BytesTx
		} else if !a4 && !b4 {
			ps66 += b.PacketsTx
			ps66 += a.PacketsTx
			bs66 += b.BytesTx
			bs66 += a.BytesTx
		}
	}
	c.Assert(s.metrics.forwarded44Packets.Value(), qt.Equals, int64(ps44))
	c.Assert(s.metrics.forwarded46Packets.Value(), qt.Equals, int64(ps46))
	c.Assert(s.metrics.forwarded64Packets.Value(), qt.Equals, int64(ps64))
	c.Assert(s.metrics.forwarded66Packets.Value(), qt.Equals, int64(ps66))
	c.Assert(s.metrics.forwarded44Bytes.Value(), qt.Equals, int64(bs44))
	c.Assert(s.metrics.forwarded46Bytes.Value(), qt.Equals, int64(bs46))
	c.Assert(s.metrics.forwarded64Bytes.Value(), qt.Equals, int64(bs64))
	c.Assert(s.metrics.forwarded66Bytes.Value(), qt.Equals, int64(bs66))
	c.Assert(s.metrics.endpoints.Value(), qt.Equals, int64(es))

	c.Assert(metricForwarded44Packets.Value(), qt.Equals, int64(ps44))
	c.Assert(metricForwarded46Packets.Value(), qt.Equals, int64(ps46))
	c.Assert(metricForwarded64Packets.Value(), qt.Equals, int64(ps64))
	c.Assert(metricForwarded66Packets.Value(), qt.Equals, int64(ps66))
	c.Assert(metricForwarded44Bytes.Value(), qt.Equals, int64(bs44))
	c.Assert(metricForwarded46Bytes.Value(), qt.Equals, int64(bs46))
	c.Assert(metricForwarded64Bytes.Value(), qt.Equals, int64(bs64))
	c.Assert(metricForwarded66Bytes.Value(), qt.Equals, int64(bs66))
	c.Assert(metricEndpoints.Value(), qt.Equals, int64(es))
}

func TestMetrics(t *testing.T) {
	c := qt.New(t)
	resetClientMetrics()
	r := &usermetric.Registry{}
	m := registerMetrics(r)

	// Expect certain prom names registered.
	have := r.MetricNames()
	want := []string{
		"tailscaled_relay_forwarded_packets_total",
		"tailscaled_relay_forwarded_bytes_total",
		"tailscaled_relay_endpoints_total",
	}
	slices.Sort(have)
	slices.Sort(want)
	c.Assert(have, qt.CmpEquals(), want)

	// Validate addEndpoints.
	m.addEndpoints(1)
	c.Assert(m.endpoints.Value(), qt.Equals, int64(1))
	c.Assert(metricEndpoints.Value(), qt.Equals, int64(1))
	m.addEndpoints(-1)
	c.Assert(m.endpoints.Value(), qt.Equals, int64(0))
	c.Assert(metricEndpoints.Value(), qt.Equals, int64(0))

	// Validate countForwarded.
	var (
		ip4 = netip.AddrFrom4([4]byte{1, 1, 1, 1})
		ip6 = netip.AddrFrom16([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	)
	m.countForwarded(ip4, ip4, []byte{1})
	c.Assert(m.forwarded44Bytes.Value(), qt.Equals, int64(1))
	c.Assert(m.forwarded44Packets.Value(), qt.Equals, int64(1))
	c.Assert(metricForwarded44Bytes.Value(), qt.Equals, int64(1))
	c.Assert(metricForwarded44Packets.Value(), qt.Equals, int64(1))

	m.countForwarded(ip4, ip6, []byte{1, 2})
	c.Assert(m.forwarded46Bytes.Value(), qt.Equals, int64(2))
	c.Assert(m.forwarded46Packets.Value(), qt.Equals, int64(1))
	c.Assert(metricForwarded46Bytes.Value(), qt.Equals, int64(2))
	c.Assert(metricForwarded46Packets.Value(), qt.Equals, int64(1))

	m.countForwarded(ip6, ip4, []byte{1, 2, 3})
	c.Assert(m.forwarded64Bytes.Value(), qt.Equals, int64(3))
	c.Assert(m.forwarded64Packets.Value(), qt.Equals, int64(1))
	c.Assert(metricForwarded64Bytes.Value(), qt.Equals, int64(3))
	c.Assert(metricForwarded64Packets.Value(), qt.Equals, int64(1))

	m.countForwarded(ip6, ip6, []byte{1, 2, 3, 4})
	c.Assert(m.forwarded66Bytes.Value(), qt.Equals, int64(4))
	c.Assert(m.forwarded66Packets.Value(), qt.Equals, int64(1))
	c.Assert(metricForwarded66Bytes.Value(), qt.Equals, int64(4))
	c.Assert(metricForwarded66Packets.Value(), qt.Equals, int64(1))
}
