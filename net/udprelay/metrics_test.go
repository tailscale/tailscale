// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"slices"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/util/usermetric"
)

func TestMetrics(t *testing.T) {
	c := qt.New(t)
	deregisterMetrics()
	r := &usermetric.Registry{}
	m := registerMetrics(r)

	// Expect certain prom names registered.
	have := r.MetricNames()
	want := []string{
		"tailscaled_peer_relay_forwarded_packets_total",
		"tailscaled_peer_relay_forwarded_bytes_total",
		"tailscaled_peer_relay_endpoints_total",
	}
	slices.Sort(have)
	slices.Sort(want)
	c.Assert(have, qt.CmpEquals(), want)

	// Validate addEndpoints.
	m.addEndpoints(1)
	c.Assert(m.endpoints.Value(), qt.Equals, int64(1))
	c.Assert(cMetricEndpoints.Value(), qt.Equals, int64(1))
	m.addEndpoints(-1)
	c.Assert(m.endpoints.Value(), qt.Equals, int64(0))
	c.Assert(cMetricEndpoints.Value(), qt.Equals, int64(0))

	// Validate countForwarded.
	m.countForwarded(true, true, 1, 1)
	c.Assert(m.forwarded44Bytes.Value(), qt.Equals, int64(1))
	c.Assert(m.forwarded44Packets.Value(), qt.Equals, int64(1))
	c.Assert(cMetricForwarded44Bytes.Value(), qt.Equals, int64(1))
	c.Assert(cMetricForwarded44Packets.Value(), qt.Equals, int64(1))

	m.countForwarded(true, false, 2, 2)
	c.Assert(m.forwarded46Bytes.Value(), qt.Equals, int64(2))
	c.Assert(m.forwarded46Packets.Value(), qt.Equals, int64(2))
	c.Assert(cMetricForwarded46Bytes.Value(), qt.Equals, int64(2))
	c.Assert(cMetricForwarded46Packets.Value(), qt.Equals, int64(2))

	m.countForwarded(false, true, 3, 3)
	c.Assert(m.forwarded64Bytes.Value(), qt.Equals, int64(3))
	c.Assert(m.forwarded64Packets.Value(), qt.Equals, int64(3))
	c.Assert(cMetricForwarded64Bytes.Value(), qt.Equals, int64(3))
	c.Assert(cMetricForwarded64Packets.Value(), qt.Equals, int64(3))

	m.countForwarded(false, false, 4, 4)
	c.Assert(m.forwarded66Bytes.Value(), qt.Equals, int64(4))
	c.Assert(m.forwarded66Packets.Value(), qt.Equals, int64(4))
	c.Assert(cMetricForwarded66Bytes.Value(), qt.Equals, int64(4))
	c.Assert(cMetricForwarded66Packets.Value(), qt.Equals, int64(4))
}
