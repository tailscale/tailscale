// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnstate_test

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestPeerStatusIsRouter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status ipnstate.PeerStatus
		want   bool
	}{
		{
			name:   "empty",
			status: ipnstate.PeerStatus{},
			want:   false,
		},
		{
			name: "invalid",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{})),
			},
			want: false,
		},
		{
			name: "plain-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
				})),
			},
			want: false,
		},
		{
			name: "plain-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				})),
			},
			want: false,
		},
		{
			name: "plain-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				})),
			},
			want: false,
		},
		{
			name: "exit-node-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("0.0.0.0/0"),
				})),
			},
			want: true,
		},
		{
			name: "exit-node-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("::/0"),
				})),
			},
			want: true,
		},
		{
			name: "exit-node-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				})),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv4",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("192.0.2.0/24"),
				})),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("2001:db8::/32"),
				})),
			},
			want: true,
		},
		{
			name: "subnet-router-ipv4-ipv6",
			status: ipnstate.PeerStatus{
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0::1"),
				},
				AllowedIPs: new(views.SliceOf([]netip.Prefix{
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					netip.MustParsePrefix("192.0.2.0/24"),
					netip.MustParsePrefix("2001:db8::/32"),
				})),
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.status.IsRouter(); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}
