// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestIssue1416RIB(t *testing.T) {
	const ribHex = `32 00 05 10 30 00 00 00 00 00 00 00 04 00 00 00 14 12 04 00 06 03 06 00 65 6e 30 ac 87 a3 19 7f 82 00 00 00 0e 12 00 00 00 00 06 00 91 e0 f0 01 00 00`
	rtmMsg, err := hex.DecodeString(strings.ReplaceAll(ribHex, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rtmMsg)
	if err != nil {
		t.Logf("ParseRIB: %v", err)
		t.Skip("skipping on known failure; see https://github.com/tailscale/tailscale/issues/1416")
		t.Fatal(err)
	}
	t.Logf("Got: %#v", msgs)
}

func TestSkipRouteMessage(t *testing.T) {
	m := &darwinRouteMon{logf: t.Logf}
	dst := &route.Inet6Addr{IP: [16]byte{0x26, 0x07}} // 2607:: (global unicast)
	tests := []struct {
		name string
		msg  *route.RouteMessage
		want bool
	}{
		{
			name: "rtm_miss",
			msg:  &route.RouteMessage{Type: unix.RTM_MISS, Addrs: []route.Addr{unix.RTAX_DST: dst}},
			want: true,
		},
		{
			name: "rtm_add",
			msg:  &route.RouteMessage{Type: unix.RTM_ADD, Addrs: []route.Addr{unix.RTAX_DST: dst}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.skipRouteMessage(tt.msg); got != tt.want {
				t.Errorf("skipRouteMessage = %v; want %v", got, tt.want)
			}
		})
	}
}
