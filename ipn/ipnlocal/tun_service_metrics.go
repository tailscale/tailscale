// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve && !ts_omit_usermetrics

package ipnlocal

import (
	"expvar"
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/util/usermetric"
)

// tunServiceMetricsState manages metrics for kernel TUN Service traffic.
// Counter series are retained for the lifetime of the process.
type tunServiceMetricsState struct {
	inbound  *usermetric.MultiLabelMap[serveLabels]
	outbound *usermetric.MultiLabelMap[serveLabels]

	enabled bool
}

func (m *tunServiceMetricsState) init(sys *tsd.System) {
	m.inbound = usermetric.NewMultiLabelMapWithRegistry[serveLabels](
		sys.UserMetricsRegistry(),
		"tailscaled_tun_service_inbound_bytes_total",
		"counter",
		"IP packet bytes received from peers through TUN-mode Tailscale Services.")
	m.outbound = usermetric.NewMultiLabelMapWithRegistry[serveLabels](
		sys.UserMetricsRegistry(),
		"tailscaled_tun_service_outbound_bytes_total",
		"counter",
		"IP packet bytes sent to peers through TUN-mode Tailscale Services.")

	if sys.IsNetstack() {
		return
	}
	if _, ok := sys.Tun.GetOK(); !ok {
		return
	}
	m.enabled = true
}

// updateLocked updates TUN Service counters. b.mu must be held.
func (m *tunServiceMetricsState) updateLocked(b *LocalBackend) {
	if !m.enabled {
		return
	}

	var countersByPrefix *bart.Table[tstun.PacketMetricCounters]
	if b.serveConfig.Valid() {
		nonTUNServices := make(map[tailcfg.ServiceName]struct{})
		for service, cfg := range b.serveConfig.Services().All() {
			if service != "" && !cfg.Tun() {
				nonTUNServices[service] = struct{}{}
			}
		}
		for ip, service := range b.ipVIPServiceMap {
			if service == "" {
				continue
			}
			// Userspace Serve Services are counted by tailscaled_serve_*.
			if _, ok := nonTUNServices[service]; ok {
				continue
			}

			key := serveLabels{Service: service.String()}
			inbound := ensureIntCounter(m.inbound, key)
			outbound := ensureIntCounter(m.outbound, key)
			if inbound == nil || outbound == nil {
				continue
			}
			if countersByPrefix == nil {
				countersByPrefix = new(bart.Table[tstun.PacketMetricCounters])
			}
			countersByPrefix.Insert(netip.PrefixFrom(ip, ip.BitLen()), tstun.PacketMetricCounters{
				Inbound:  inbound,
				Outbound: outbound,
			})
		}
	}

	if tun, ok := b.sys.Tun.GetOK(); ok {
		tun.SetPacketMetricCounters(countersByPrefix)
	}
}

func ensureIntCounter(m *usermetric.MultiLabelMap[serveLabels], key serveLabels) *expvar.Int {
	m.Add(key, 0)
	v, _ := m.Get(key).(*expvar.Int)
	return v
}
