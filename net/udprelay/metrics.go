// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"expvar"
	"net/netip"

	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
)

var (
	metricForwarded44Packets = clientmetric.NewCounter("udprelay_forwarded_packets_udp4_udp4")
	metricForwarded46Packets = clientmetric.NewCounter("udprelay_forwarded_packets_udp4_udp6")
	metricForwarded64Packets = clientmetric.NewCounter("udprelay_forwarded_packets_udp6_udp4")
	metricForwarded66Packets = clientmetric.NewCounter("udprelay_forwarded_packets_udp6_udp6")

	metricForwarded44Bytes = clientmetric.NewCounter("udprelay_forwarded_bytes_udp4_udp4")
	metricForwarded46Bytes = clientmetric.NewCounter("udprelay_forwarded_bytes_udp4_udp6")
	metricForwarded64Bytes = clientmetric.NewCounter("udprelay_forwarded_bytes_udp6_udp4")
	metricForwarded66Bytes = clientmetric.NewCounter("udprelay_forwarded_bytes_udp6_udp6")

	metricEndpoints = clientmetric.NewGauge("udprelay_endpoints")
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

// registerMetrics publishes user metric counters for peer relay server.
func registerMetrics(reg *usermetric.Registry) *metrics {
	var (
		forwardedPackets = usermetric.NewMultiLabelMapWithRegistry[forwardedLabel](
			reg,
			"tailscaled_relay_forwarded_packets_total",
			"counter",
			"Counts the number of packets forwarded via Peer Relay",
		)
		forwardedBytes = usermetric.NewMultiLabelMapWithRegistry[forwardedLabel](
			reg,
			"tailscaled_relay_forwarded_bytes_total",
			"counter",
			"Counts the number of bytes forwarded via Peer Relay",
		)
		endpoints = usermetric.NewMultiLabelMapWithRegistry[endpointLabel](
			reg,
			"tailscaled_relay_endpoints_total",
			"gauge",
			"Renders the current number of registered Peer Relay endpoints",
		)
		forwarded44 = forwardedLabel{transportIn: transportUDP4, transportOut: transportUDP4}
		forwarded46 = forwardedLabel{transportIn: transportUDP4, transportOut: transportUDP6}
		forwarded64 = forwardedLabel{transportIn: transportUDP6, transportOut: transportUDP4}
		forwarded66 = forwardedLabel{transportIn: transportUDP6, transportOut: transportUDP6}
		m           = new(metrics)
	)

	// Publish user metrics.
	forwardedPackets.Set(forwarded44, &m.forwarded44Packets)
	forwardedPackets.Set(forwarded46, &m.forwarded46Packets)
	forwardedPackets.Set(forwarded64, &m.forwarded64Packets)
	forwardedPackets.Set(forwarded66, &m.forwarded66Packets)

	forwardedBytes.Set(forwarded44, &m.forwarded44Bytes)
	forwardedBytes.Set(forwarded46, &m.forwarded46Bytes)
	forwardedBytes.Set(forwarded64, &m.forwarded64Bytes)
	forwardedBytes.Set(forwarded66, &m.forwarded66Bytes)

	endpoints.Set(endpointLabel{}, &m.endpoints)

	return m
}

func (m *metrics) addEndpoints(value int) {
	m.endpoints.Add(int64(value))
	metricEndpoints.Add(int64(value))
}

func (m *metrics) countForwarded(from, to netip.Addr, b []byte) {
	in4, out4 := from.Is4(), to.Is4()
	bytes := int64(len(b))
	if in4 && out4 {
		m.forwarded44Packets.Add(1)
		m.forwarded44Bytes.Add(bytes)
		metricForwarded44Packets.Add(1)
		metricForwarded44Bytes.Add(bytes)
	} else if in4 && !out4 {
		m.forwarded46Packets.Add(1)
		m.forwarded46Bytes.Add(bytes)
		metricForwarded46Packets.Add(1)
		metricForwarded46Bytes.Add(bytes)
	} else if !in4 && out4 {
		m.forwarded64Packets.Add(1)
		m.forwarded64Bytes.Add(bytes)
		metricForwarded64Packets.Add(1)
		metricForwarded64Bytes.Add(bytes)
	} else {
		m.forwarded66Packets.Add(1)
		m.forwarded66Bytes.Add(bytes)
		metricForwarded66Packets.Add(1)
		metricForwarded66Bytes.Add(bytes)
	}
}
