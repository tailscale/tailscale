// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

var (
	lanResolver     = netip.MustParseAddr("192.168.1.1")
	altLANResolver  = netip.MustParseAddr("192.168.1.53")
	systemResolver  = netip.Addr{} // the zero Addr means "whatever the OS picks"
	portalLoginHost = "notonthelan.someplace.com"
)

// splitResolvers is a set of resolvers that answer differently depending on
// which one is asked, which is the whole point of preferring the local
// network's over the system's.
type splitResolvers struct {
	d *Detector
	// asked records every resolver we queried, in order.
	asked []netip.Addr
}

// newSplitResolvers returns a Detector whose local network resolvers are
// locals, and whose resolvers answer out of answers.
//
// answers is keyed by resolver address, with [systemResolver] standing for the
// system resolver. A resolver with no entry never answers at all, which is what
// a query swallowed by the tunnel looks like from here.
func newSplitResolvers(t *testing.T, locals []netip.Addr, answers map[netip.Addr]map[string][]string) *splitResolvers {
	sr := &splitResolvers{d: NewDetector(t.Logf)}
	sr.d.SetLocalNetworkResolvers(func() []netip.Addr { return locals })
	sr.d.lookupIPFn = func(_ context.Context, server netip.Addr, host string) ([]netip.Addr, error) {
		sr.asked = append(sr.asked, server)
		a, ok := answers[server]
		if !ok {
			return nil, errNoAnswer
		}
		return answerFrom(a, host)
	}
	return sr
}

// TestLookupIPPrefersLocalNetworkResolvers checks that we ask the network we're
// investigating before we ask the system.
//
// On a node using an exit node the system resolver is quad-100, whose answers
// come from the far end of the tunnel — the one place a captive portal has
// already cut us off from.
func TestLookupIPPrefersLocalNetworkResolvers(t *testing.T) {
	sr := newSplitResolvers(t, []netip.Addr{lanResolver}, map[netip.Addr]map[string][]string{
		lanResolver:    {portalLoginHost: {"93.184.216.34"}},
		systemResolver: {portalLoginHost: {"10.9.9.9"}},
	})

	got, err := sr.d.lookupIP(t.Context(), portalLoginHost, 0)
	if err != nil {
		t.Fatalf("lookupIP: %v", err)
	}
	if want := []netip.Addr{netip.MustParseAddr("93.184.216.34")}; !slices.Equal(got, want) {
		t.Errorf("lookupIP = %v, want %v", got, want)
	}
	if want := []netip.Addr{lanResolver}; !slices.Equal(sr.asked, want) {
		t.Errorf("asked %v, want %v (the system resolver should not have been consulted)", sr.asked, want)
	}
}

// TestLookupIPSkipsResolversThatDoNotAnswer checks we work down the list rather
// than giving up on the first silence, and fall back to the system resolver
// when the whole local network is quiet.
func TestLookupIPSkipsResolversThatDoNotAnswer(t *testing.T) {
	tests := []struct {
		name    string
		answers map[netip.Addr]map[string][]string
		want    string
		asked   []netip.Addr
	}{
		{
			name: "second local resolver answers",
			answers: map[netip.Addr]map[string][]string{
				altLANResolver: {portalLoginHost: {"93.184.216.34"}},
				systemResolver: {portalLoginHost: {"10.9.9.9"}},
			},
			want:  "93.184.216.34",
			asked: []netip.Addr{lanResolver, altLANResolver},
		},
		{
			name: "nothing local answers",
			answers: map[netip.Addr]map[string][]string{
				systemResolver: {portalLoginHost: {"10.9.9.9"}},
			},
			want:  "10.9.9.9",
			asked: []netip.Addr{lanResolver, altLANResolver, systemResolver},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := newSplitResolvers(t, []netip.Addr{lanResolver, altLANResolver}, tt.answers)
			got, err := sr.d.lookupIP(t.Context(), portalLoginHost, 0)
			if err != nil {
				t.Fatalf("lookupIP: %v", err)
			}
			if want := []netip.Addr{netip.MustParseAddr(tt.want)}; !slices.Equal(got, want) {
				t.Errorf("lookupIP = %v, want %v", got, want)
			}
			if !slices.Equal(sr.asked, tt.asked) {
				t.Errorf("asked %v, want %v", sr.asked, tt.asked)
			}
		})
	}
}

// TestLookupIPStopsAtNXDOMAIN checks that a resolver saying the name does not
// exist ends the search.
//
// It answered, so we have our answer. Carrying on to a resolver further away
// could only turn a correct negative into a fabricated positive.
func TestLookupIPStopsAtNXDOMAIN(t *testing.T) {
	sr := newSplitResolvers(t, []netip.Addr{lanResolver, altLANResolver}, map[netip.Addr]map[string][]string{
		lanResolver:    {},
		altLANResolver: {portalLoginHost: {"93.184.216.34"}},
		systemResolver: {portalLoginHost: {"93.184.216.34"}},
	})

	if _, err := sr.d.lookupIP(t.Context(), portalLoginHost, 0); !isNotFound(err) {
		t.Errorf("lookupIP error = %v, want a not-found error", err)
	}
	if want := []netip.Addr{lanResolver}; !slices.Equal(sr.asked, want) {
		t.Errorf("asked %v, want %v", sr.asked, want)
	}
}

// TestAnnotatePortalLocalityBehindExitNode is the case this all exists for.
//
// A portal sends us to a login page by name. The user is on an exit node, so
// the system resolver leads into the tunnel and times out; only the network's
// own resolver can say where that page lives. If we don't ask it we leave
// locality unknown, callers treat unknown as on-LAN, and the user is told to
// open up their local network for a page that is out on the Internet — which
// cannot help, because the default route stays pointed at the exit node.
func TestAnnotatePortalLocalityBehindExitNode(t *testing.T) {
	tests := []struct {
		name      string
		lanAnswer string
		want      bool
	}{
		{
			name:      "login page out on the Internet",
			lanAnswer: "93.184.216.34",
			want:      false,
		},
		{
			// The same lookup, on a network whose login page is a box in the
			// wiring closet. Here opening the LAN back up does help.
			name:      "login page on the LAN",
			lanAnswer: "192.168.1.1",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := newSplitResolvers(t, []netip.Addr{lanResolver}, map[netip.Addr]map[string][]string{
				// No entry for systemResolver: quad-100 forwards through the
				// tunnel to the exit node, which is exactly what the portal is
				// blocking.
				lanResolver: {portalLoginHost: {tt.lanAnswer}},
			})

			res := Result{Verdict: VerdictPortal, PortalURL: "http://" + portalLoginHost + "/portal"}
			sr.d.annotatePortalLocality(t.Context(), &res)

			local, known := res.PortalURLIsLocal.Get()
			if !known {
				t.Fatalf("PortalURLIsLocal = %q, want it to be known", res.PortalURLIsLocal)
			}
			if local != tt.want {
				t.Errorf("PortalURLIsLocal = %v, want %v", local, tt.want)
			}
		})
	}
}

// TestLocalNetworkResolvers checks the list we work through: the OS
// configuration's servers, then the gateway, without duplicates and without the
// Tailscale resolver we're trying to get around.
func TestLocalNetworkResolvers(t *testing.T) {
	d := NewDetector(t.Logf)
	if got := d.localNetworkResolvers(); len(got) != 0 {
		t.Errorf("localNetworkResolvers with nothing configured = %v, want none", got)
	}

	d.SetLocalNetworkResolvers(func() []netip.Addr {
		return []netip.Addr{
			netip.MustParseAddr("100.100.100.100"), // quad-100, must be dropped
			lanResolver,
			netip.MustParseAddr("8.8.8.8"),
			lanResolver, // duplicate
			{},          // invalid
		}
	})
	want := []netip.Addr{lanResolver, netip.MustParseAddr("8.8.8.8")}
	if got := d.localNetworkResolvers(); !slices.Equal(got, want) {
		t.Errorf("localNetworkResolvers = %v, want %v", got, want)
	}
}
