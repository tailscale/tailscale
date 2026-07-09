// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
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

func TestConfigVAlphaToPrefs(t *testing.T) {
	aps := func(t *testing.T, strs ...string) (ret []netip.AddrPort) {
		t.Helper()
		for _, s := range strs {
			n, err := netip.ParseAddrPort(s)
			if err != nil {
				t.Fatalf("parse AddrPort %q: %v", s, err)
			}
			ret = append(ret, n)
		}
		return ret
	}

	tests := []struct {
		name string
		cfg  *ConfigVAlpha
		want MaskedPrefs
	}{
		{
			name: "nil_config",
			cfg:  nil,
			want: MaskedPrefs{},
		},
		{
			name: "relay_server_port_and_static_endpoints",
			cfg: &ConfigVAlpha{
				RelayServerPort:            new(uint16(12345)),
				RelayServerStaticEndpoints: aps(t, "[2001:db8::1]:40000", "192.0.2.1:40000"),
			},
			want: MaskedPrefs{
				Prefs: Prefs{
					RelayServerPort:            new(uint16(12345)),
					RelayServerStaticEndpoints: aps(t, "[2001:db8::1]:40000", "192.0.2.1:40000"),
				},
				RelayServerPortSet:            true,
				RelayServerStaticEndpointsSet: true,
			},
		},
		{
			// Port 0 means "pick a random unused port"; it is
			// distinct from a nil port which disables the relay
			// server. The zero value must be propagated.
			name: "relay_server_port_zero_is_random_not_disabled",
			cfg: &ConfigVAlpha{
				RelayServerPort: new(uint16(0)),
			},
			want: MaskedPrefs{
				Prefs: Prefs{
					RelayServerPort: new(uint16(0)),
				},
				RelayServerPortSet:            true,
				RelayServerStaticEndpointsSet: true,
			},
		},
		{
			name: "only_static_endpoints_set",
			cfg: &ConfigVAlpha{
				RelayServerStaticEndpoints: aps(t, "192.0.2.1:40000"),
			},
			want: MaskedPrefs{
				Prefs: Prefs{
					RelayServerStaticEndpoints: aps(t, "192.0.2.1:40000"),
				},
				RelayServerPortSet:            true,
				RelayServerStaticEndpointsSet: true,
			},
		},
		{
			// Both fields nil but masks set: the config file is the
			// source of truth, so this disables any previously
			// configured relay server.
			name: "both_nil_disables_relay_server",
			cfg:  &ConfigVAlpha{},
			want: MaskedPrefs{
				RelayServerPortSet:            true,
				RelayServerStaticEndpointsSet: true,
			},
		},
		{
			// An empty (non-nil) static endpoints slice is treated as
			// "advertise no static endpoints", disabling them.
			name: "empty_static_endpoints_disables",
			cfg: &ConfigVAlpha{
				RelayServerStaticEndpoints: []netip.AddrPort{},
			},
			want: MaskedPrefs{
				Prefs: Prefs{
					RelayServerStaticEndpoints: []netip.AddrPort{},
				},
				RelayServerPortSet:            true,
				RelayServerStaticEndpointsSet: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() unexpected error: %v", err)
			}
			// Compare only the relay-server-related fields rather than
			// the whole MaskedPrefs, since ToPrefs populates many
			// unrelated default fields (e.g. WantRunning).
			if got.RelayServerPortSet != tt.want.RelayServerPortSet {
				t.Errorf("RelayServerPortSet = %v; want %v", got.RelayServerPortSet, tt.want.RelayServerPortSet)
			}
			if got.RelayServerStaticEndpointsSet != tt.want.RelayServerStaticEndpointsSet {
				t.Errorf("RelayServerStaticEndpointsSet = %v; want %v", got.RelayServerStaticEndpointsSet, tt.want.RelayServerStaticEndpointsSet)
			}
			if !reflect.DeepEqual(got.RelayServerPort, tt.want.RelayServerPort) {
				t.Errorf("RelayServerPort = %v; want %v", got.RelayServerPort, tt.want.RelayServerPort)
			}
			if !slices.Equal(got.RelayServerStaticEndpoints, tt.want.RelayServerStaticEndpoints) {
				t.Errorf("RelayServerStaticEndpoints = %v; want %v", got.RelayServerStaticEndpoints, tt.want.RelayServerStaticEndpoints)
			}
		})
	}
}

func TestConfigVAlphaToPrefsRemoteConfig(t *testing.T) {
	for name, tt := range map[string]struct {
		cfg     ConfigVAlpha
		wantSet bool
		wantVal bool
	}{
		"absent": {ConfigVAlpha{Version: "alpha0"}, false, false},
		"true":   {ConfigVAlpha{Version: "alpha0", RemoteConfig: "true"}, true, true},
		"false":  {ConfigVAlpha{Version: "alpha0", RemoteConfig: "false"}, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			mp, err := tt.cfg.ToPrefs()
			if err != nil {
				t.Fatal(err)
			}
			if mp.RemoteConfigSet != tt.wantSet {
				t.Errorf("RemoteConfigSet = %v; want %v", mp.RemoteConfigSet, tt.wantSet)
			}
			if mp.RemoteConfig != tt.wantVal {
				t.Errorf("RemoteConfig = %v; want %v", mp.RemoteConfig, tt.wantVal)
			}
		})
	}
}
