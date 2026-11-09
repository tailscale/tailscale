// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd || openbsd

package netmon

import (
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func defaultRouteMsg(index, flags int) *route.RouteMessage {
	return &route.RouteMessage{
		Index: index,
		Flags: flags,
		Addrs: []route.Addr{
			unix.RTAX_DST:     &route.Inet4Addr{},
			unix.RTAX_GATEWAY: &route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}},
			unix.RTAX_NETMASK: &route.Inet4Addr{},
		},
	}
}

func TestFindDefaultGatewayRoute(t *testing.T) {
	const (
		up      = unix.RTF_UP | unix.RTF_STATIC
		gateway = up | unix.RTF_GATEWAY
	)
	tests := []struct {
		name string
		msgs []route.Message
		want int // wanted route's Index; 0 for none
	}{
		{
			name: "none",
			want: 0,
		},
		{
			name: "plain",
			msgs: []route.Message{defaultRouteMsg(4, gateway)},
			want: 4,
		},
		{
			name: "interface-route-without-gateway",
			msgs: []route.Message{defaultRouteMsg(5, up)},
			want: 0,
		},
		{
			name: "prefer-unscoped",
			msgs: []route.Message{
				defaultRouteMsg(4, gateway|rtfIfScope),
				defaultRouteMsg(6, gateway),
			},
			want: 6,
		},
		{
			// A TUN-mode VPN/proxy owns the global default (no gateway) and
			// the physical interface's default became scoped.
			name: "only-scoped-under-tun-vpn",
			msgs: []route.Message{
				defaultRouteMsg(5, up),
				defaultRouteMsg(4, gateway|rtfIfScope),
				defaultRouteMsg(8, up|rtfIfScope),
			},
			want: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := findDefaultGatewayRoute(tt.msgs)
			got := 0
			if rm != nil {
				got = rm.Index
			}
			if got != tt.want {
				t.Errorf("findDefaultGatewayRoute index = %d; want %d", got, tt.want)
			}
		})
	}
}
