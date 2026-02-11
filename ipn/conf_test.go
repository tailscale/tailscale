// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"net/netip"
	"testing"

	"tailscale.com/types/preftype"
)

// TestConfigVAlpha_ToPrefs_AdvertiseRoutes tests that ToPrefs validates routes
// provided directly as netip.Prefix values (not parsed from JSON).
func TestConfigVAlpha_ToPrefs_AdvertiseRoutes(t *testing.T) {
	tests := []struct {
		name    string
		routes  []netip.Prefix
		wantErr bool
	}{
		{
			name: "valid_routes",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
			wantErr: false,
		},
		{
			name: "invalid_ipv4_route",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.1/24"),
			},
			wantErr: true,
		},
		{
			name: "invalid_ipv6_route",
			routes: []netip.Prefix{
				netip.MustParsePrefix("2a01:4f9:c010:c015::1/64"),
			},
			wantErr: true,
		},
		{
			name: "mixed_valid_and_invalid",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.1/16"),
				netip.MustParsePrefix("2001:db8::/32"),
				netip.MustParsePrefix("2a01:4f9::1/64"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ConfigVAlpha{
				Version:         "alpha0",
				AdvertiseRoutes: tt.routes,
			}

			_, err := cfg.ToPrefs()
			if (err != nil) != tt.wantErr {
				t.Errorf("cfg.ToPrefs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigVAlpha_ToPrefs_LinuxPacketMarks(t *testing.T) {
	tests := []struct {
		name    string
		marks   *preftype.LinuxPacketMarks
		wantSet bool
		wantErr bool
	}{
		{
			name:    "nil_unset",
			marks:   nil,
			wantSet: false,
		},
		{
			name: "valid",
			marks: &preftype.LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantSet: true,
		},
		{
			name: "invalid_overlap",
			marks: &preftype.LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x40000,
			},
			wantErr: true,
		},
		{
			name: "invalid_outside_mask",
			marks: &preftype.LinuxPacketMarks{
				FwmarkMask:      0x0f0000,
				SubnetRouteMark: 0x400000,
				BypassMark:      0x80000,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ConfigVAlpha{
				Version:          "alpha0",
				LinuxPacketMarks: tt.marks,
			}
			mp, err := cfg.ToPrefs()
			if (err != nil) != tt.wantErr {
				t.Fatalf("cfg.ToPrefs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if mp.LinuxPacketMarksSet != tt.wantSet {
				t.Errorf("LinuxPacketMarksSet = %v, want %v", mp.LinuxPacketMarksSet, tt.wantSet)
			}
			if tt.wantSet && mp.LinuxPacketMarks != tt.marks {
				t.Errorf("LinuxPacketMarks = %v, want %v", mp.LinuxPacketMarks, tt.marks)
			}
		})
	}
}
