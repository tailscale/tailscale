// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"net/netip"
	"testing"

	"tailscale.com/net/netmon"
)

func TestProtocolsRequiredForForwarding(t *testing.T) {
	state := &netmon.State{
		InterfaceIPs: map[string][]netip.Prefix{
			"em0": {netip.MustParsePrefix("192.168.1.5/24")},
		},
	}
	tests := []struct {
		name   string
		routes []netip.Prefix
		wantV4 bool
		wantV6 bool
	}{
		{"none", nil, false, false},
		{"v4only", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, true, false},
		{"v6only", []netip.Prefix{netip.MustParsePrefix("2000::/3")}, false, true},
		{
			"both",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2000::/3")},
			true, true,
		},
		{
			// Advertising a route to one of our own local IPs doesn't
			// require forwarding, so it must not trigger a warning.
			"local single IP",
			[]netip.Prefix{netip.MustParsePrefix("192.168.1.5/32")},
			false, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v4, v6 := protocolsRequiredForForwarding(tt.routes, state)
			if v4 != tt.wantV4 || v6 != tt.wantV6 {
				t.Errorf("got v4=%v v6=%v, want v4=%v v6=%v", v4, v6, tt.wantV4, tt.wantV6)
			}
		})
	}
}

// TestCheckIPForwardingFreeBSDNoRoutes verifies we don't shell out to sysctl
// (and so can't warn) when there are no routes needing forwarding. This is the
// path taken by a FreeBSD node that isn't a subnet router.
func TestCheckIPForwardingFreeBSDNoRoutes(t *testing.T) {
	state := &netmon.State{}
	warn, err := checkIPForwardingFreeBSD(nil, state)
	if warn != nil || err != nil {
		t.Fatalf("got warn=%v err=%v, want both nil", warn, err)
	}
}
