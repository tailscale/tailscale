// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"net/netip"
	"testing"
)

// TestConfigVAlpha_AdvertiseRoutes_InvalidPrefix tests that the config file
// path does not validate that advertised routes have properly masked prefixes.
// Specifically, invalid prefixes like "::1/64" should be rejected.
func TestConfigVAlpha_AdvertiseRoutes_InvalidPrefix(t *testing.T) {
	tests := []struct {
		name        string
		jsonConfig  string
		wantErr     bool // currently false, should be true after fix
		expectValid bool // should the parsed prefix be valid (== Masked())
	}{
		{
			name: "valid_ipv4",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["10.0.0.0/24"]
			}`,
			wantErr:     false,
			expectValid: true,
		},
		{
			name: "valid_ipv6",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["2a01:4f9:c010:c015::/64"]
			}`,
			wantErr:     false,
			expectValid: true,
		},
		{
			name: "invalid_ipv4_non_address_bits",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["10.0.0.1/24"]
			}`,
			wantErr:     true, // Now properly validated
			expectValid: false,
		},
		{
			name: "invalid_ipv6_non_address_bits",
			jsonConfig: `{
				"version": "alpha0",
				"advertiseRoutes": ["2a01:4f9:c010:c015::1/64"]
			}`,
			wantErr:     true, // Now properly validated
			expectValid: false,
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
			wantErr:     true,  // Now properly validated
			expectValid: false, // at least one route is invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ConfigVAlpha
			err := json.Unmarshal([]byte(tt.jsonConfig), &cfg)
			if err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			// Check if advertised routes are valid
			if len(cfg.AdvertiseRoutes) > 0 {
				allValid := true
				for _, route := range cfg.AdvertiseRoutes {
					if route != route.Masked() {
						t.Logf("Route %s has non-address bits set (should be %s)",
							route, route.Masked())
						allValid = false
					}
				}

				if allValid != tt.expectValid {
					t.Errorf("Route validity = %v, want %v", allValid, tt.expectValid)
				}
			}

			// Now test that ToPrefs() validates and rejects invalid routes
			mp, err := cfg.ToPrefs()
			if (err != nil) != tt.wantErr {
				t.Errorf("cfg.ToPrefs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expected an error, we're done
			if tt.wantErr {
				if err != nil {
					t.Logf("Expected error received: %v", err)
				}
				return
			}

			// For valid routes, verify they were copied correctly
			for i, route := range mp.AdvertiseRoutes {
				if route != route.Masked() {
					t.Errorf("Invalid route %s in MaskedPrefs.AdvertiseRoutes[%d]",
						route, i)
				}
			}
		})
	}
}

// TestMaskedPrefs_AdvertiseRoutes_Validation tests that validation should
// happen when routes are set via different code paths.
func TestMaskedPrefs_AdvertiseRoutes_Validation(t *testing.T) {
	tests := []struct {
		name    string
		routes  []netip.Prefix
		wantErr bool // should be true for invalid prefixes after fix
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
				netip.MustParsePrefix("10.0.0.1/24"), // has non-address bits
			},
			wantErr: true, // Now properly validated
		},
		{
			name: "invalid_ipv6_route",
			routes: []netip.Prefix{
				netip.MustParsePrefix("2a01:4f9:c010:c015::1/64"), // has non-address bits
			},
			wantErr: true, // Now properly validated
		},
		{
			name: "mixed_valid_and_invalid",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),    // valid
				netip.MustParsePrefix("192.168.1.1/16"), // invalid
				netip.MustParsePrefix("2001:db8::/32"),  // valid
				netip.MustParsePrefix("2a01:4f9::1/64"), // invalid
			},
			wantErr: true, // Now properly validated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with these routes
			cfg := ConfigVAlpha{
				Version:         "alpha0",
				AdvertiseRoutes: tt.routes,
			}

			mp, err := cfg.ToPrefs()
			if (err != nil) != tt.wantErr {
				t.Errorf("cfg.ToPrefs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expected an error, we're done
			if tt.wantErr {
				if err != nil {
					t.Logf("Expected error received: %v", err)
				}
				return
			}

			// For valid routes, verify they are properly masked
			for _, route := range mp.AdvertiseRoutes {
				if route != route.Masked() {
					t.Errorf("Invalid route %s in MaskedPrefs (should be %s)",
						route, route.Masked())
				}
			}
		})
	}
}
