// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"fmt"
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
	for k := range cMetricEndpoints {
		c.Check(cMetricEndpoints[k].Value(), qt.Equals, int64(0))
	}
}

func TestMetricsEndpointTransitions(t *testing.T) {
	c := qt.New(t)
	var states = []endpointState{
		endpointClosed,
		endpointConnecting,
		endpointOpen,
	}
	for _, a := range states {
		for _, b := range states {
			t.Run(fmt.Sprintf("%s-%s", a, b), func(t *testing.T) {
				deregisterMetrics()
				r := &usermetric.Registry{}
				m := registerMetrics(r)
				m.updateEndpoint(a, b)
				var wantA, wantB int64
				switch {
				case a == b:
					wantA, wantB = 0, 0
				case a == endpointClosed:
					wantA, wantB = 0, 1
				case b == endpointClosed:
					wantA, wantB = -1, 0
				default:
					wantA, wantB = -1, 1
				}
				if a != endpointClosed {
					c.Check(m.endpoints[a].Value(), qt.Equals, wantA)
					c.Check(cMetricEndpoints[a].Value(), qt.Equals, wantA)
				}
				if b != endpointClosed {
					c.Check(m.endpoints[b].Value(), qt.Equals, wantB)
					c.Check(cMetricEndpoints[b].Value(), qt.Equals, wantB)
				}
			})
		}
	}
}
