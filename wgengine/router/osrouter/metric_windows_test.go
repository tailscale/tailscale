// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"net/netip"
	"testing"

	"tailscale.com/net/tsaddr"
)

func TestWindowsRouteMetric(t *testing.T) {
	tests := []struct {
		name  string
		route netip.Prefix
		want  uint32
	}{
		{
			name:  "default_route_v4",
			route: netip.MustParsePrefix("0.0.0.0/0"),
			want:  0,
		},
		{
			name:  "default_route_v6",
			route: netip.MustParsePrefix("::/0"),
			want:  0,
		},
		{
			name:  "tailscale_service_ip_v4_single_host",
			route: netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32),
			want:  0,
		},
		{
			name:  "tailscale_service_ip_v6_single_host",
			route: netip.PrefixFrom(tsaddr.TailscaleServiceIPv6(), 128),
			want:  0,
		},
		{
			name:  "advertised_subnet_v4",
			route: netip.MustParsePrefix("192.168.1.0/24"),
			want:  windowsSubnetRouteMetric,
		},
		{
			name:  "advertised_subnet_v6",
			route: netip.MustParsePrefix("fd00::/64"),
			want:  windowsSubnetRouteMetric,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowsRouteMetric(tt.route); got != tt.want {
				t.Fatalf("windowsRouteMetric(%v)=%v; want %v", tt.route, got, tt.want)
			}
		})
	}
}

