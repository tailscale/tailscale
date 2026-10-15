// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
)

func TestAcceptRoutesPrefsPersistence(t *testing.T) {
	// Stored filters remain meaningful with route acceptance disabled.
	want := &Prefs{
		AcceptRoutesAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
		AcceptRoutesDeny:  []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")},
		Hostname:          "route-filter-test",
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Prefs
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Equals(want) {
		t.Fatalf("round-trip prefs = %v; want %v", got, want)
	}
	if !slices.Equal(got.AcceptRoutesAllow, want.AcceptRoutesAllow) || !slices.Equal(got.AcceptRoutesDeny, want.AcceptRoutesDeny) {
		t.Fatal("JSON round-trip did not preserve route filters")
	}

	// Existing saved profiles have neither field and continue to accept all
	// subnet routes when RouteAll is set.
	var legacy Prefs
	if err := json.Unmarshal([]byte(`{"RouteAll":true}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if !legacy.RouteAll || len(legacy.AcceptRoutesAllow) != 0 || len(legacy.AcceptRoutesDeny) != 0 {
		t.Fatalf("legacy prefs = %v", legacy)
	}
}

func TestAcceptRoutesPrefsCopies(t *testing.T) {
	p := &Prefs{
		AcceptRoutesAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AcceptRoutesDeny:  []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")},
	}
	v := p.View()
	other := netip.MustParsePrefix("192.0.2.0/24")
	for _, copy := range []*Prefs{p.Clone(), v.AsStruct()} {
		if !copy.Equals(p) {
			t.Fatal("copy differs from original")
		}
		copy.AcceptRoutesAllow[0] = other
		if copy.Equals(p) {
			t.Fatal("Equals ignores a changed allow filter")
		}
		if v.AcceptRoutesAllow().At(0) != netip.MustParsePrefix("10.0.0.0/8") {
			t.Fatal("mutating copied allow filter changed original")
		}
		copy.AcceptRoutesAllow[0] = p.AcceptRoutesAllow[0]
		copy.AcceptRoutesDeny[0] = other
		if copy.Equals(p) {
			t.Fatal("Equals ignores a changed deny filter")
		}
		if v.AcceptRoutesDeny().At(0) != netip.MustParsePrefix("10.2.0.0/24") {
			t.Fatal("mutating copied deny filter changed original")
		}
	}

	// Slice views may expose copies, but never their backing slices.
	v.AcceptRoutesAllow().AsSlice()[0] = other
	v.AcceptRoutesDeny().AsSlice()[0] = other
	if p.AcceptRoutesAllow[0] == other || p.AcceptRoutesDeny[0] == other {
		t.Fatal("slice view exposed mutable route filters")
	}
}

func TestAcceptRoutesMaskedPrefs(t *testing.T) {
	original := &Prefs{
		RouteAll:          true,
		AcceptRoutesAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AcceptRoutesDeny:  []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")},
		Hostname:          "route-filter-test",
		CorpDNS:           true,
	}
	for _, allow := range []bool{true, false} {
		name := "deny"
		if allow {
			name = "allow"
		}
		t.Run(name, func(t *testing.T) {
			for _, clear := range []bool{false, true} {
				p := original.Clone()
				var routes []netip.Prefix
				if !clear {
					routes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
				}
				mp := &MaskedPrefs{
					AcceptRoutesAllowSet: allow,
					AcceptRoutesDenySet:  !allow,
				}
				want := original.Clone()
				if allow {
					mp.AcceptRoutesAllow = routes
					want.AcceptRoutesAllow = routes
				} else {
					mp.AcceptRoutesDeny = routes
					want.AcceptRoutesDeny = routes
				}
				if mp.IsEmpty() {
					t.Fatal("filter edit has empty mask")
				}
				p.ApplyEdits(mp)
				if !p.Equals(want) || !slices.Equal(p.AcceptRoutesAllow, want.AcceptRoutesAllow) || !slices.Equal(p.AcceptRoutesDeny, want.AcceptRoutesDeny) {
					t.Fatalf("clear=%v: edited prefs = %v; want %v", clear, p, want)
				}
			}
		})
	}
}
