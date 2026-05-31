// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"testing"
)

func TestParseAcceptRoutes(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		goos            string
		wantRouteAll    bool
		wantAccepted    []netip.Prefix
		wantErr         bool
	}{
		{
			name:         "empty string uses default (linux)",
			input:        "",
			goos:         "linux",
			wantRouteAll: false,
			wantAccepted: nil,
			wantErr:      false,
		},
		{
			name:         "empty string uses default (windows)",
			input:        "",
			goos:         "windows",
			wantRouteAll: true,
			wantAccepted: nil,
			wantErr:      false,
		},
		{
			name:         "true value",
			input:        "true",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: nil,
			wantErr:      false,
		},
		{
			name:         "false value",
			input:        "false",
			goos:         "linux",
			wantRouteAll: false,
			wantAccepted: nil,
			wantErr:      false,
		},
		{
			name:         "flag without value (backward compat)",
			input:        "true", // This is what the custom flag sets when used without value
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: nil,
			wantErr:      false,
		},
		{
			name:         "single CIDR",
			input:        "10.0.0.0/8",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			wantErr:      false,
		},
		{
			name:         "multiple CIDRs",
			input:        "10.0.0.0/8,192.168.0.0/16",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			wantErr: false,
		},
		{
			name:         "CIDRs with spaces",
			input:        "10.0.0.0/8, 192.168.0.0/16 , 172.16.0.0/12",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("172.16.0.0/12"),
			},
			wantErr: false,
		},
		{
			name:         "IPv6 CIDR",
			input:        "fd7a:115c:a1e0::/48",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
			wantErr:      false,
		},
		{
			name:         "mixed IPv4 and IPv6",
			input:        "10.0.0.0/8,fd7a:115c:a1e0::/48",
			goos:         "linux",
			wantRouteAll: true,
			wantAccepted: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			input:   "10.0.0.0/99",
			goos:    "linux",
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   "not-a-cidr",
			goos:    "linux",
			wantErr: true,
		},
		{
			name:    "empty list",
			input:   ",,,",
			goos:    "linux",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRouteAll, gotAccepted, err := parseAcceptRoutes(tt.input, tt.goos)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAcceptRoutes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotRouteAll != tt.wantRouteAll {
				t.Errorf("parseAcceptRoutes() routeAll = %v, want %v", gotRouteAll, tt.wantRouteAll)
			}
			if len(gotAccepted) != len(tt.wantAccepted) {
				t.Errorf("parseAcceptRoutes() acceptedRoutes length = %v, want %v", len(gotAccepted), len(tt.wantAccepted))
				return
			}
			for i := range gotAccepted {
				if gotAccepted[i] != tt.wantAccepted[i] {
					t.Errorf("parseAcceptRoutes() acceptedRoutes[%d] = %v, want %v", i, gotAccepted[i], tt.wantAccepted[i])
				}
			}
		})
	}
}
