// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"net/netip"
	"testing"
)

// TestConfigVAlpha_AdvertiseRoutes_InvalidPrefix tests that ToPrefs rejects
// advertised route prefixes with non-address bits set (e.g., 10.0.0.1/24
// instead of 10.0.0.0/24).
func TestConfigVAlpha_AdvertiseRoutes_InvalidPrefix(t *testing.T) {
	tests := []struct {
		name       string
		jsonConfig string
		wantErr    bool
	}{
		{
			name: "valid_ipv4",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["10.0.0.0/24"]
			}`,
			wantErr: false,
		},
		{
			name: "valid_ipv6",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["2a01:4f9:c010:c015::/64"]
			}`,
			wantErr: false,
		},
		{
			name: "invalid_ipv4_non_address_bits",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["10.0.0.1/24"]
			}`,
			wantErr: true,
		},
		{
			name: "invalid_ipv6_non_address_bits",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["2a01:4f9:c010:c015::1/64"]
			}`,
			wantErr: true,
		},
		{
			name: "invalid_ipv6_multiple_routes",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": [
					"10.0.0.0/24",
					"2a01:4f9:c010:c015::1/64"
				]
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ConfigVAlpha
			if err := json.Unmarshal([]byte(tt.jsonConfig), &cfg); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			_, err := cfg.ToPrefs()
			if (err != nil) != tt.wantErr {
				t.Errorf("cfg.ToPrefs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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
