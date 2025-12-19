// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"expvar"

	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
)

var (
	// Although we only need one, [clientmetric.AggregateCounter] is the only
	// method to embed [expvar.Int] into client metrics.
	cMetricForwarded44Packets = clientmetric.NewAggregateCounter("udprelay_forwarded_packets_udp4_udp4")
	cMetricForwarded46Packets = clientmetric.NewAggregateCounter("udprelay_forwarded_packets_udp4_udp6")
	cMetricForwarded64Packets = clientmetric.NewAggregateCounter("udprelay_forwarded_packets_udp6_udp4")
	cMetricForwarded66Packets = clientmetric.NewAggregateCounter("udprelay_forwarded_packets_udp6_udp6")

	cMetricForwarded44Bytes = clientmetric.NewAggregateCounter("udprelay_forwarded_bytes_udp4_udp4")
	cMetricForwarded46Bytes = clientmetric.NewAggregateCounter("udprelay_forwarded_bytes_udp4_udp6")
	cMetricForwarded64Bytes = clientmetric.NewAggregateCounter("udprelay_forwarded_bytes_udp6_udp4")
	cMetricForwarded66Bytes = clientmetric.NewAggregateCounter("udprelay_forwarded_bytes_udp6_udp6")

	// [clientmetric.Gauge] does not let us embed existing counters,
	// [metrics.addEndpoints] records data into client and user gauges independently.
	cMetricEndpoints = clientmetric.NewGauge("udprelay_endpoints")
)

type transport string

const (
	transportUDP4 transport = "udp4"
	transportUDP6 transport = "udp6"
)

type forwardedLabel struct {
	transportIn  transport `prom:"transport_in"`
	transportOut transport `prom:"transport_out"`
}

type endpointLabel struct {
}

type metrics struct {
	forwarded44Packets expvar.Int
	forwarded46Packets expvar.Int
	forwarded64Packets expvar.Int
	forwarded66Packets expvar.Int

	forwarded44Bytes expvar.Int
	forwarded46Bytes expvar.Int
	forwarded64Bytes expvar.Int
	forwarded66Bytes expvar.Int

	endpoints expvar.Int
}

// registerMetrics publishes user and client metric counters for peer relay server.
//
// It will panic if called twice with the same registry.
func registerMetrics(reg *usermetric.Registry) *metrics {
	var (
		uMetricForwardedPackets = usermetric.NewMultiLabelMapWithRegistry[forwardedLabel](
			reg,
			"tailscaled_peer_relay_forwarded_packets_total",
			"counter",
			"Number of packets forwarded via Peer Relay",
		)
		uMetricForwardedBytes = usermetric.NewMultiLabelMapWithRegistry[forwardedLabel](
			reg,
			"tailscaled_peer_relay_forwarded_bytes_total",
			"counter",
			"Number of bytes forwarded via Peer Relay",
		)
		uMetricEndpoints = usermetric.NewMultiLabelMapWithRegistry[endpointLabel](
			reg,
			"tailscaled_peer_relay_endpoints_total",
			"gauge",
			"Number of allocated Peer Relay endpoints",
		)
		forwarded44 = forwardedLabel{transportIn: transportUDP4, transportOut: transportUDP4}
		forwarded46 = forwardedLabel{transportIn: transportUDP4, transportOut: transportUDP6}
		forwarded64 = forwardedLabel{transportIn: transportUDP6, transportOut: transportUDP4}
		forwarded66 = forwardedLabel{transportIn: transportUDP6, transportOut: transportUDP6}
		m           = new(metrics)
	)

	// Publish user metrics.
	uMetricForwardedPackets.Set(forwarded44, &m.forwarded44Packets)
	uMetricForwardedPackets.Set(forwarded46, &m.forwarded46Packets)
	uMetricForwardedPackets.Set(forwarded64, &m.forwarded64Packets)
	uMetricForwardedPackets.Set(forwarded66, &m.forwarded66Packets)

	uMetricForwardedBytes.Set(forwarded44, &m.forwarded44Bytes)
	uMetricForwardedBytes.Set(forwarded46, &m.forwarded46Bytes)
	uMetricForwardedBytes.Set(forwarded64, &m.forwarded64Bytes)
	uMetricForwardedBytes.Set(forwarded66, &m.forwarded66Bytes)

	uMetricEndpoints.Set(endpointLabel{}, &m.endpoints)

	// Publish client metrics.
	cMetricForwarded44Packets.Register(&m.forwarded44Packets)
	cMetricForwarded46Packets.Register(&m.forwarded46Packets)
	cMetricForwarded64Packets.Register(&m.forwarded64Packets)
	cMetricForwarded66Packets.Register(&m.forwarded66Packets)
	cMetricForwarded44Bytes.Register(&m.forwarded44Bytes)
	cMetricForwarded46Bytes.Register(&m.forwarded46Bytes)
	cMetricForwarded64Bytes.Register(&m.forwarded64Bytes)
	cMetricForwarded66Bytes.Register(&m.forwarded66Bytes)

	return m
}

// addEndpoints updates the total endpoints gauge. Value can be negative.
// It records two gauges independently, see [cMetricEndpoints] doc.
func (m *metrics) addEndpoints(value int64) {
	m.endpoints.Add(value)
	cMetricEndpoints.Add(value)
}

// countForwarded records user and client metrics according to the
// inbound and outbound address families.
func (m *metrics) countForwarded(in4, out4 bool, bytes, packets int64) {
	if in4 && out4 {
		m.forwarded44Packets.Add(packets)
		m.forwarded44Bytes.Add(bytes)
	} else if in4 && !out4 {
		m.forwarded46Packets.Add(packets)
		m.forwarded46Bytes.Add(bytes)
	} else if !in4 && out4 {
		m.forwarded64Packets.Add(packets)
		m.forwarded64Bytes.Add(bytes)
	} else {
		m.forwarded66Packets.Add(packets)
		m.forwarded66Bytes.Add(bytes)
	}
}

// deregisterMetrics unregisters the underlying expvar counters
// from clientmetrics.
func deregisterMetrics() {
	cMetricForwarded44Packets.UnregisterAll()
	cMetricForwarded46Packets.UnregisterAll()
	cMetricForwarded64Packets.UnregisterAll()
	cMetricForwarded66Packets.UnregisterAll()
	cMetricForwarded44Bytes.UnregisterAll()
	cMetricForwarded46Bytes.UnregisterAll()
	cMetricForwarded64Bytes.UnregisterAll()
	cMetricForwarded66Bytes.UnregisterAll()
	cMetricEndpoints.Set(0)
}
