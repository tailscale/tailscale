// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestCheckFunnelAccess(t *testing.T) {
	tests := []struct {
		caps    []string
		wantErr bool
	}{
		{[]string{}, true}, // No "funnel" attribute
		{[]string{tailcfg.CapabilityWarnFunnelNoInvite}, true},
		{[]string{tailcfg.CapabilityWarnFunnelNoHTTPS}, true},
		{[]string{tailcfg.NodeAttrFunnel}, false},
	}
	for _, tt := range tests {
		err := CheckFunnelAccess(tt.caps)
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
