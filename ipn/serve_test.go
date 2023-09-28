// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	caps := func(c ...tailcfg.NodeCapability) []tailcfg.NodeCapability { return c }
	const portAttr tailcfg.NodeCapability = "https://tailscale.com/cap/funnel-ports?ports=443,8080-8090,8443,"
	tests := []struct {
		port    uint16
		caps    []tailcfg.NodeCapability
		wantErr bool
	}{
		{443, caps(portAttr), true}, // No "funnel" attribute
		{443, caps(portAttr, tailcfg.NodeAttrFunnel), true},
		{443, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8443, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8321, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
		{8083, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), false},
		{8091, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
		{3000, caps(portAttr, tailcfg.CapabilityHTTPS, tailcfg.NodeAttrFunnel), true},
	}
	for _, tt := range tests {
		cm := tailcfg.NodeCapMap{}
		for _, c := range tt.caps {
			cm[c] = nil
		}
		err := CheckFunnelAccess(tt.port, &ipnstate.PeerStatus{CapMap: cm})
		switch {
		case err != nil && tt.wantErr,
			err == nil && !tt.wantErr:
			continue
		case tt.wantErr:
			t.Fatalf("got no error, want error")
		case !tt.wantErr:
			t.Fatalf("got error %v, want no error", err)
		}
	}
}
