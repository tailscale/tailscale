// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"testing"
)

func TestFirstIPString(t *testing.T) {
	v4 := netip.MustParseAddr("198.51.100.1")
	v6 := netip.MustParseAddr("3fff::1")

	tests := []struct {
		name  string
		addrs []netip.Addr
		want4 bool
		want6 bool
		want  string
	}{
		{
			name:  "empty",
			addrs: nil,
			want:  "",
		},
		{
			name:  "default returns first",
			addrs: []netip.Addr{v4, v6},
			want:  "198.51.100.1",
		},
		{
			name:  "want4",
			addrs: []netip.Addr{v4, v6},
			want4: true,
			want:  "198.51.100.1",
		},
		{
			name:  "want6",
			addrs: []netip.Addr{v4, v6},
			want6: true,
			want:  "3fff::1",
		},
		{
			name:  "want4 with v6 first",
			addrs: []netip.Addr{v6, v4},
			want4: true,
			want:  "198.51.100.1",
		},
		{
			name:  "want6 with v4 first",
			addrs: []netip.Addr{v4, v6},
			want6: true,
			want:  "3fff::1",
		},
		{
			name:  "want4 but only v6 available",
			addrs: []netip.Addr{v6},
			want4: true,
			want:  "",
		},
		{
			name:  "want6 but only v4 available",
			addrs: []netip.Addr{v4},
			want6: true,
			want:  "",
		},
		{
			name:  "multiple v4 returns first v4",
			addrs: []netip.Addr{netip.MustParseAddr("198.51.100.2"), v4, v6},
			want4: true,
			want:  "198.51.100.2",
		},
		{
			name:  "multiple v6 returns first v6",
			addrs: []netip.Addr{v4, netip.MustParseAddr("3fff::2"), v6},
			want6: true,
			want:  "3fff::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstIPString(tt.addrs, tt.want4, tt.want6)
			if got != tt.want {
				t.Errorf("firstIPString(%v, %v, %v) = %q, want %q", tt.addrs, tt.want4, tt.want6, got, tt.want)
			}
		})
	}
}
