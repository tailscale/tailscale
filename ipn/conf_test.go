// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/types/ptr"
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

// TestConfigVAlpha_Tailnet verifies that the Tailnet field round-trips
// through JSON, accepting both Tailnet ID and Legacy ID values verbatim.
func TestConfigVAlpha_Tailnet(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{
			name: "tailnet_id",
			json: `{"version":"alpha0","Tailnet":"tail1234.ts.net"}`,
			want: "tail1234.ts.net",
		},
		{
			name: "legacy_id_domain",
			json: `{"version":"alpha0","Tailnet":"example.com"}`,
			want: "example.com",
		},
		{
			name: "legacy_id_email",
			json: `{"version":"alpha0","Tailnet":"user@gmail.com"}`,
			want: "user@gmail.com",
		},
		{
			name: "unset",
			json: `{"version":"alpha0"}`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ConfigVAlpha
			if err := json.Unmarshal([]byte(tt.json), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got := ""
			if cfg.Tailnet != nil {
				got = *cfg.Tailnet
			}
			if got != tt.want {
				t.Errorf("Tailnet = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConfigVAlpha_RedactedJSON verifies that RedactedJSON removes the AuthKey
// secret while preserving non-secret fields, so the loaded config can be safely
// logged at startup.
func TestConfigVAlpha_RedactedJSON(t *testing.T) {
	key := "tskey-auth-abc123-secret"
	cfg := &ConfigVAlpha{
		Version:  "alpha0",
		AuthKey:  &key,
		Hostname: ptr.To("my-node"),
	}
	got, err := cfg.RedactedJSON()
	if err != nil {
		t.Fatalf("RedactedJSON: %v", err)
	}
	if strings.Contains(string(got), key) {
		t.Errorf("RedactedJSON leaked AuthKey secret: %s", got)
	}
	if !strings.Contains(string(got), "my-node") {
		t.Errorf("RedactedJSON dropped non-secret field: %s", got)
	}
	// The original config must be unmodified by redaction.
	if cfg.AuthKey == nil || *cfg.AuthKey != key {
		t.Errorf("RedactedJSON mutated the original AuthKey: %v", cfg.AuthKey)
	}

	// A nil AuthKey must not produce a redaction placeholder.
	cfg.AuthKey = nil
	got, err = cfg.RedactedJSON()
	if err != nil {
		t.Fatalf("RedactedJSON (no authkey): %v", err)
	}
	if strings.Contains(string(got), "redacted") {
		t.Errorf("RedactedJSON added placeholder for unset AuthKey: %s", got)
	}
}
