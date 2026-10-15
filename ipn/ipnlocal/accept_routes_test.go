// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestCheckAcceptRoutes(t *testing.T) {
	tests := []struct {
		name    string
		routes  []netip.Prefix
		wantErr string
	}{
		{name: "nil"},
		{name: "empty", routes: []netip.Prefix{}},
		{
			name: "IPv4_and_IPv6",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.30.0.0/24"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
		},
		{name: "IPv4_wildcard", routes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{name: "IPv6_wildcard", routes: []netip.Prefix{netip.MustParsePrefix("::/0")}},
		// A filter may cover multiple 4via6 sites, even though this prefix is
		// too broad to advertise as a 4via6 subnet route.
		{name: "4via6_umbrella", routes: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a::/64")}},
		{name: "invalid", routes: []netip.Prefix{{}}, wantErr: "invalid prefix"},
		{name: "IPv4_host_bits", routes: []netip.Prefix{netip.MustParsePrefix("10.2.0.1/24")}, wantErr: "expected 10.2.0.0/24"},
		{name: "IPv6_host_bits", routes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/64")}, wantErr: "expected 2001:db8::/64"},
		{name: "mapped_IPv4", routes: []netip.Prefix{netip.MustParsePrefix("::ffff:10.2.0.0/120")}, wantErr: "IPv4-mapped IPv6"},
		{
			name: "valid_then_invalid",
			routes: []netip.Prefix{
				netip.MustParsePrefix("10.30.0.0/24"),
				netip.MustParsePrefix("10.2.0.1/24"),
			},
			wantErr: "expected 10.2.0.0/24",
		},
	}
	for _, tt := range tests {
		for _, allow := range []bool{true, false} {
			flag := "accept-routes-deny"
			if allow {
				flag = "accept-routes-allow"
			}
			t.Run(flag+"/"+tt.name, func(t *testing.T) {
				for _, routeAll := range []bool{false, true} {
					p := &ipn.Prefs{RouteAll: routeAll}
					if allow {
						p.AcceptRoutesAllow = tt.routes
					} else {
						p.AcceptRoutesDeny = tt.routes
					}
					err := checkAcceptRoutes(p)
					if tt.wantErr == "" {
						if err != nil {
							t.Fatalf("RouteAll=%v: %v", routeAll, err)
						}
					} else if err == nil || !strings.Contains(err.Error(), flag) || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("RouteAll=%v: error = %v; want %q and %q", routeAll, err, flag, tt.wantErr)
					}
				}
			})
		}
	}
}

// TestEditPrefsAcceptRoutes verifies that LocalAPI preference edits go through
// filter validation and that a rejected edit leaves the current prefs intact.
func TestEditPrefsAcceptRoutes(t *testing.T) {
	b := newTestLocalBackend(t)
	want, err := b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AcceptRoutesAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			AcceptRoutesDeny:  []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")},
			Hostname:          "route-filter-test",
		},
		RouteAllSet:          true,
		AcceptRoutesAllowSet: true,
		AcceptRoutesDenySet:  true,
		HostnameSet:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, allow := range []bool{true, false} {
		mp := &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				Hostname: "must-not-be-applied",
			},
			AcceptRoutesAllowSet: allow,
			AcceptRoutesDenySet:  !allow,
			HostnameSet:          true,
		}
		invalid := []netip.Prefix{netip.MustParsePrefix("10.2.0.1/24")}
		if allow {
			mp.AcceptRoutesAllow = invalid
		} else {
			mp.AcceptRoutesDeny = invalid
		}
		if err := b.CheckPrefs(&mp.Prefs); err == nil {
			t.Fatal("CheckPrefs accepted invalid route filter")
		}
		if _, err := b.EditPrefs(mp); err == nil {
			t.Fatal("EditPrefs accepted invalid route filter")
		}
		if got := b.Prefs().AsStruct(); !got.Equals(want.AsStruct()) {
			t.Fatalf("rejected edit changed prefs: got %v, want %v", got, want)
		}
	}

	got, err := b.EditPrefs(&ipn.MaskedPrefs{AcceptRoutesDenySet: true})
	if err != nil {
		t.Fatal(err)
	}
	wantCleared := want.AsStruct()
	wantCleared.AcceptRoutesDeny = nil
	if !got.AsStruct().Equals(wantCleared) {
		t.Fatalf("clearing deny changed other prefs: got %v, want %v", got, wantCleared)
	}
}
