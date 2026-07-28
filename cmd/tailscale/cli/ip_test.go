// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestPeerMatchingIP(t *testing.T) {
	st := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")},
			},
			key.NewNode().Public(): {
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
			},
		},
	}

	tests := []struct {
		name    string
		ipStr   string
		wantOK  bool
		wantIPs []netip.Addr
	}{
		{
			name:    "match_self_v4",
			ipStr:   "100.64.0.1",
			wantOK:  true,
			wantIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		},
		{
			name:    "match_self_v6",
			ipStr:   "fd7a:115c:a1e0::1",
			wantOK:  true,
			wantIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
		},
		{
			name:    "match_peer_v4",
			ipStr:   "100.64.0.2",
			wantOK:  true,
			wantIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")},
		},
		{
			name:    "match_peer_single_ip",
			ipStr:   "100.64.0.3",
			wantOK:  true,
			wantIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		},
		{
			name:   "no_match",
			ipStr:  "100.64.0.99",
			wantOK: false,
		},
		{
			name:   "invalid_ip",
			ipStr:  "not-an-ip",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps, ok := peerMatchingIP(st, tt.ipStr)
			if ok != tt.wantOK {
				t.Fatalf("peerMatchingIP(%q) ok = %v, want %v", tt.ipStr, ok, tt.wantOK)
			}
			if ok {
				if len(ps.TailscaleIPs) != len(tt.wantIPs) {
					t.Fatalf("got %d IPs, want %d", len(ps.TailscaleIPs), len(tt.wantIPs))
				}
				for i, ip := range ps.TailscaleIPs {
					if ip != tt.wantIPs[i] {
						t.Errorf("IP[%d] = %v, want %v", i, ip, tt.wantIPs[i])
					}
				}
			}
		})
	}
}

func TestAllIPsForServiceWithIP(t *testing.T) {
	services := map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		"svc:web": {
			Name: "svc:web",
			Addrs: []netip.Addr{
				netip.MustParseAddr("100.100.0.1"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::1"),
			},
		},
		"svc:api": {
			Name:  "svc:api",
			Addrs: []netip.Addr{netip.MustParseAddr("100.100.0.2")},
		},
	}
	// Services should have at most 2 addrs (one v4, one v6), but
	// we handle more gracefully if the server ever returns them.
	multiAddr := map[tailcfg.ServiceName]tailcfg.ServiceDetails{
		"svc:multi": {
			Name: "svc:multi",
			Addrs: []netip.Addr{
				netip.MustParseAddr("100.100.0.3"),
				netip.MustParseAddr("100.100.0.4"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::3"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::4"),
			},
		},
	}

	tests := []struct {
		name     string
		services map[tailcfg.ServiceName]tailcfg.ServiceDetails
		ip       netip.Addr
		wantIPs  []netip.Addr
	}{
		{
			name:     "match_service_v4",
			services: services,
			ip:       netip.MustParseAddr("100.100.0.1"),
			wantIPs: []netip.Addr{
				netip.MustParseAddr("100.100.0.1"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::1"),
			},
		},
		{
			name:     "match_service_v6",
			services: services,
			ip:       netip.MustParseAddr("fd7a:115c:a1e0:ab12::1"),
			wantIPs: []netip.Addr{
				netip.MustParseAddr("100.100.0.1"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::1"),
			},
		},
		{
			name:     "match_single_addr_service",
			services: services,
			ip:       netip.MustParseAddr("100.100.0.2"),
			wantIPs:  []netip.Addr{netip.MustParseAddr("100.100.0.2")},
		},
		{
			name:     "match_service_multiple_addrs_v4",
			services: multiAddr,
			ip:       netip.MustParseAddr("100.100.0.3"),
			wantIPs: []netip.Addr{
				netip.MustParseAddr("100.100.0.3"),
				netip.MustParseAddr("100.100.0.4"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::3"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::4"),
			},
		},
		{
			name:     "match_service_multiple_addrs_v6",
			services: multiAddr,
			ip:       netip.MustParseAddr("fd7a:115c:a1e0:ab12::3"),
			wantIPs: []netip.Addr{
				netip.MustParseAddr("100.100.0.3"),
				netip.MustParseAddr("100.100.0.4"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::3"),
				netip.MustParseAddr("fd7a:115c:a1e0:ab12::4"),
			},
		},
		{
			name:     "no_match",
			services: services,
			ip:       netip.MustParseAddr("100.100.0.99"),
			wantIPs:  nil,
		},
		{
			name:     "empty_services",
			services: nil,
			ip:       netip.MustParseAddr("100.100.0.1"),
			wantIPs:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allIPsForServiceWithIP(tt.services, tt.ip)
			if len(got) != len(tt.wantIPs) {
				t.Fatalf("allIPsForServiceWithIP(%v) returned %d IPs, want %d", tt.ip, len(got), len(tt.wantIPs))
			}
			for i, ip := range got {
				if ip != tt.wantIPs[i] {
					t.Errorf("IP[%d] = %v, want %v", i, ip, tt.wantIPs[i])
				}
			}
		})
	}
}
