// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package fallbacknames

import "testing"

func TestIsTailscaleHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"controlplane.tailscale.com", true},
		{"log.tailscale.com", true},
		{"log.tailscale.io", true},
		{"login.us.tailscale.com", true},
		{"Controlplane.Tailscale.COM.", true},
		{"tailscale.com", true},
		{"headscale.example.com", false},
		{"faketailscale.com", false},
		{"tailscale.com.example.net", false},
		{"log.tailscale.com/x.tailscale.com", false},
		{"foo bar.tailscale.com", false},
		{"foo..tailscale.com", false},
		{".tailscale.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsTailscaleHost(tt.host); got != tt.want {
			t.Errorf("IsTailscaleHost(%q) = %v; want %v", tt.host, got, tt.want)
		}
	}
}
