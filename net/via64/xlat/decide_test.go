// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlat

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/preftype"
)

var x = Xlat{X4: netip.MustParseAddr("192.0.0.6")}

func on(adv ...string) Desired {
	d := Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, ForwardingV4: true, ForwardingV6: true}
	for _, a := range adv {
		d.Advertised = append(d.Advertised, netip.MustParsePrefix(a))
	}
	return d
}

func TestDecideOff(t *testing.T) {
	oneSite := on("10.1.0.174/32", "fd7a:115c:a1e0:b1a:0:1790::/96")
	tests := []struct {
		name string
		mod  func(*Desired)
		why  string
	}{
		{"netfilter-off", func(d *Desired) { d.Netfilter = preftype.NetfilterOff }, "netfilter mode is off"},
		{"netfilter-nodivert", func(d *Desired) { d.Netfilter = preftype.NetfilterNoDivert }, "netfilter mode is nodivert"},
		{"no-snat", func(d *Desired) { d.SNAT = false }, "SNAT for subnet routes is off"},
		{"no-tun-ipv6", func(d *Desired) { d.TunIPv6 = false }, "IPv6 is not usable on the Tailscale interface"},
		{"no-v4-forwarding", func(d *Desired) { d.ForwardingV4 = false }, "net.ipv4.ip_forward is not 1"},
		{"no-v6-forwarding", func(d *Desired) { d.ForwardingV6 = false }, "net.ipv6.conf.all.forwarding is not 1"},
		{"firewalld", func(d *Desired) { d.Firewalld = true }, "firewalld is running (not yet supported)"},
		{"forward-drop", func(d *Desired) { d.ForwardDrop = "inet filter forward" }, "nftables chain inet filter forward drops forwarded traffic, out of reach of Tailscale's rules"},
		{"no-via", func(d *Desired) { d.Advertised = d.Advertised[:1] }, "no 4via6 routes are advertised"},
		// At startup there are neither routes nor netfilter yet; report the routes, which are not logged.
		{"no-via-before-netfilter", func(d *Desired) { d.Advertised, d.Netfilter = nil, preftype.NetfilterOff }, "no 4via6 routes are advertised"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := oneSite
			d.Advertised = slices.Clone(oneSite.Advertised)
			tt.mod(&d)
			prefixes, why := decide(d, x)
			if prefixes != nil || why != tt.why {
				t.Errorf("decide = %v, %q; want nil, %q", prefixes, why, tt.why)
			}
		})
	}
	if _, why := decide(oneSite, Xlat{}); why != "X4 invalid IP is not a usable IPv4 address" {
		t.Errorf("zero X4: why = %q", why)
	}
}

func TestDecideOneSite(t *testing.T) {
	prefixes, why := decide(on("10.1.0.174/32", "fd7a:115c:a1e0:b1a:0:1790::/96"), x)
	if why != "" || !slices.Equal(prefixes, []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}) {
		t.Fatalf("decide = %v, %q", prefixes, why)
	}
	if got, want := x.X6(), netip.MustParseAddr("fd7a:115c:a1e0:b1a:ff:ffff:c000:6"); got != want {
		t.Errorf("X6 = %v; want %v", got, want)
	}
}

func TestDecideAnyNumberOfSites(t *testing.T) {
	var adv []string
	for id := 1; id <= 40; id++ { // far more sites than any per-site address block would allow
		adv = append(adv, fmt.Sprintf("fd7a:115c:a1e0:b1a:0:%x::/96", id))
	}
	adv = append(adv,
		"fd7a:115c:a1e0:b1a:0:7:a01:100/120", // inside site 7's /96; kept, harmless
		"fd7a:115c:a1e0:b1a:0:1::/96",        // duplicate
		"fd7a:115c:a1e0:b1a:1::/96",          // site 0x10000: invalid, ignored
	)
	prefixes, why := decide(on(adv...), x)
	if why != "" || len(prefixes) != 41 {
		t.Fatalf("Decide returned %d prefixes, %q; want 41", len(prefixes), why)
	}
	if !slices.IsSortedFunc(prefixes, netipx.ComparePrefix) {
		t.Errorf("prefixes not sorted: %v", prefixes)
	}
}

func TestCanonicalIsNeverAdvertisable(t *testing.T) {
	if !tsaddr.IsViaPrefix(Canonical) || Canonical.Bits() != 96 {
		t.Fatalf("Canonical %v is not a /96 in the via range", Canonical)
	}
	a := Canonical.Addr().As16()
	if a[8] != 0 {
		t.Errorf("Canonical bits 64-71 = %#x; RFC 6052 needs 0", a[8])
	}
	if prefixes, _ := decide(on(Canonical.String()), x); len(prefixes) != 0 {
		t.Errorf("Decide accepted the canonical prefix as an advertised route: %v", prefixes)
	}
}
