// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netaddr

import (
	"net/netip"
	"testing"
)

func TestIPIsMulticast(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"224.0.0.1", true},
		{"239.255.255.255", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.ip)
		if got := IPIsMulticast(ip); got != tt.want {
			t.Errorf("IPIsMulticast(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAllowFormat(t *testing.T) {
	_ = AllowFormat("test")
	// Just verify it doesn't panic
}
