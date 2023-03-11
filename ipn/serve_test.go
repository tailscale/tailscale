// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	portAttr := "https://tailscale.com/cap/funnel-ports?ports=443,8080-8090,8443,"
	tests := []struct {
		port    uint16
		caps    []string
		wantErr bool
	}{
		{443, []string{portAttr}, true}, // No "funnel" attribute
		{443, []string{portAttr, tailcfg.CapabilityWarnFunnelNoInvite}, true},
		{443, []string{portAttr, tailcfg.CapabilityWarnFunnelNoHTTPS}, true},
		{443, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8443, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8321, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
		{8083, []string{portAttr, tailcfg.NodeAttrFunnel}, false},
		{8091, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
		{3000, []string{portAttr, tailcfg.NodeAttrFunnel}, true},
	}
	for _, tt := range tests {
		err := CheckFunnelAccess(tt.port, tt.caps)
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
