// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestEndpointTracker(t *testing.T) {
	local := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("192.168.1.1:12345"),
		Type: tailcfg.EndpointLocal,
	}

	stun4_1 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("1.2.3.4:12345"),
		Type: tailcfg.EndpointSTUN,
	}
	stun4_2 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("5.6.7.8:12345"),
		Type: tailcfg.EndpointSTUN,
	}

	stun6_1 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("[2a09:8280:1::1111]:12345"),
		Type: tailcfg.EndpointSTUN,
	}
	stun6_2 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("[2a09:8280:1::2222]:12345"),
		Type: tailcfg.EndpointSTUN,
	}

	start := time.Unix(1681503440, 0)

	steps := []struct {
		name string
		now  time.Time
		eps  []tailcfg.Endpoint
		want []tailcfg.Endpoint
	}{
		{
			name: "initial endpoints",
			now:  start,
			eps:  []tailcfg.Endpoint{local, stun4_1, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "no change",
			now:  start.Add(1 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_1, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "missing stun4",
			now:  start.Add(2 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "missing stun6",
			now:  start.Add(3 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "multiple STUN addresses within timeout",
			now:  start.Add(4 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_2, stun6_2},
			want: []tailcfg.Endpoint{local, stun4_1, stun4_2, stun6_1, stun6_2},
		},
		{
			name: "endpoint extended",
			now:  start.Add(3*time.Minute + endpointTrackerLifetime - 1),
			eps:  []tailcfg.Endpoint{local},
			want: []tailcfg.Endpoint{
				local, stun4_2, stun6_2,
				// stun4_1 had its lifetime extended by the
				// "missing stun6" test above to that start
				// time plus the lifetime, while stun6 should
				// have expired a minute sooner. It should thus
				// be in this returned list.
				stun4_1,
			},
		},
		{
			name: "after timeout",
			now:  start.Add(4*time.Minute + endpointTrackerLifetime + 1),
			eps:  []tailcfg.Endpoint{local, stun4_2, stun6_2},
			want: []tailcfg.Endpoint{local, stun4_2, stun6_2},
		},
		{
			name: "after timeout still caches",
			now:  start.Add(4*time.Minute + endpointTrackerLifetime + time.Minute),
			eps:  []tailcfg.Endpoint{local},
			want: []tailcfg.Endpoint{local, stun4_2, stun6_2},
		},
	}

	var et endpointTracker
	for _, tt := range steps {
		t.Logf("STEP: %s", tt.name)

		got := et.update(tt.now, tt.eps)

		// Sort both arrays for comparison
		slices.SortFunc(got, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})
		slices.SortFunc(tt.want, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("endpoints mismatch\ngot: %+v\nwant: %+v", got, tt.want)
		}
	}
}

func TestEndpointTrackerMaxNum(t *testing.T) {
	start := time.Unix(1681503440, 0)

	var allEndpoints []tailcfg.Endpoint // all created endpoints
	mkEp := func(i int) tailcfg.Endpoint {
		ep := tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), uint16(i)),
			Type: tailcfg.EndpointSTUN,
		}
		allEndpoints = append(allEndpoints, ep)
		return ep
	}

	var et endpointTracker

	// Add more endpoints to the list than our limit
	for i := 0; i <= endpointTrackerMaxPerAddr; i++ {
		et.update(start.Add(time.Duration(i)*time.Second), []tailcfg.Endpoint{mkEp(10000 + i)})
	}

	// Now add two more, slightly later
	got := et.update(start.Add(1*time.Minute), []tailcfg.Endpoint{
		mkEp(10100),
		mkEp(10101),
	})

	// We expect to get the last N endpoints per our per-Addr limit, since
	// all of the endpoints have the same netip.Addr. The first endpoint(s)
	// that we added were dropped because we had more than the limit for
	// this Addr.
	want := allEndpoints[len(allEndpoints)-endpointTrackerMaxPerAddr:]

	compareEndpoints := func(got, want []tailcfg.Endpoint) {
		t.Helper()
		slices.SortFunc(want, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})
		slices.SortFunc(got, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("endpoints mismatch\ngot: %+v\nwant: %+v", got, want)
		}
	}
	compareEndpoints(got, want)

	// However, if we have more than our limit of endpoints passed in to
	// the endpointTracker, we will return all of them (even if they're for
	// the same address).
	var inputEps []tailcfg.Endpoint
	for i := range endpointTrackerMaxPerAddr + 5 {
		inputEps = append(inputEps, tailcfg.Endpoint{
			Addr: netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), 10200+uint16(i)),
			Type: tailcfg.EndpointSTUN,
		})
	}

	want = inputEps
	got = et.update(start.Add(2*time.Minute), inputEps)
	compareEndpoints(got, want)
}
