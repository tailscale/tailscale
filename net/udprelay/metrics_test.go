// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"slices"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/util/usermetric"
)

func TestMetricsLifecycle(t *testing.T) {
	c := qt.New(t)
	deregisterMetrics()
	r := &usermetric.Registry{}
	m := registerMetrics(r)

	// Expect certain prom names registered.
	have := r.MetricNames()
	want := []string{
		"tailscaled_peer_relay_forwarded_packets_total",
		"tailscaled_peer_relay_forwarded_bytes_total",
		"tailscaled_peer_relay_endpoints",
	}
	slices.Sort(have)
	slices.Sort(want)
	c.Assert(have, qt.CmpEquals(), want)

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

	// Validate client metrics deregistration.
	m.updateEndpoint(endpointClosed, endpointOpen)
	deregisterMetrics()
	c.Check(cMetricForwarded44Bytes.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded44Packets.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded46Bytes.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded46Packets.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded64Bytes.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded64Packets.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded66Bytes.Value(), qt.Equals, int64(0))
	c.Check(cMetricForwarded66Packets.Value(), qt.Equals, int64(0))
	c.Check(cMetricEndpoints[endpointOpen].Value(), qt.Equals, int64(0))
}

func TestMetricsEndpointTransitions(t *testing.T) {
	c := qt.New(t)
	for _, tc := range []struct {
		name              string
		leaving, entering endpointState
		wantOpen          int64
		wantSemi          int64
		wantBound         int64
	}{
		{"closed-open", endpointClosed, endpointOpen, 1, 0, 0},
		{"open-semi_bound", endpointOpen, endpointSemiBound, -1, 1, 0},
		{"semi_bound-bound", endpointSemiBound, endpointBound, 0, -1, 1},
		{"open-closed", endpointOpen, endpointClosed, -1, 0, 0},
		{"semi_bound-closed", endpointSemiBound, endpointClosed, 0, -1, 0},
		{"bound-closed", endpointBound, endpointClosed, 0, 0, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deregisterMetrics()
			r := &usermetric.Registry{}
			m := registerMetrics(r)

			m.updateEndpoint(tc.leaving, tc.entering)
			c.Check(m.endpoints[endpointOpen].Value(), qt.Equals, tc.wantOpen)
			c.Check(m.endpoints[endpointSemiBound].Value(), qt.Equals, tc.wantSemi)
			c.Check(m.endpoints[endpointBound].Value(), qt.Equals, tc.wantBound)

			// Verify client metrics match
			c.Check(cMetricEndpoints[endpointOpen].Value(), qt.Equals, tc.wantOpen)
			c.Check(cMetricEndpoints[endpointSemiBound].Value(), qt.Equals, tc.wantSemi)
			c.Check(cMetricEndpoints[endpointBound].Value(), qt.Equals, tc.wantBound)
		})
	}
}
