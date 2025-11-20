// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestConsolidateRoutes(t *testing.T) {
	parseRoutes := func(routes ...string) []netip.Prefix {
		parsed := make([]netip.Prefix, 0, len(routes))
		for _, routeString := range routes {
			route, err := netip.ParsePrefix(routeString)
			if err != nil {
				t.Fatal(err)
			}
			parsed = append(parsed, route)
		}
		return parsed
	}

	tests := []struct {
		name string
		cfg  *Config
		want *Config
	}{
		{
			"nil cfg",
			nil,
			nil,
		},
		{
			"single route",
			&Config{Routes: parseRoutes("10.0.0.0/32")},
			&Config{Routes: parseRoutes("10.0.0.0/32")},
		},
		{
			"two routes from different families",
			&Config{Routes: parseRoutes("10.0.0.0/32", "2603:1030:c02::/47")},
			&Config{Routes: parseRoutes("10.0.0.0/32", "2603:1030:c02::/47")},
		},
		{
			"two disjoint routes",
			&Config{Routes: parseRoutes("10.0.0.0/32", "10.0.2.0/32")},
			&Config{Routes: parseRoutes("10.0.0.0/32", "10.0.2.0/32")},
		},
		{
			"two overlapping routes",
			&Config{Routes: parseRoutes("10.0.0.0/32", "10.0.0.0/31")},
			&Config{Routes: parseRoutes("10.0.0.0/31")},
		},
	}

	cr := &consolidatingRouter{logf: t.Logf}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := cr.consolidateRoutes(test.cfg)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("wrong result; (-got+want):%v", diff)
			}
		})
	}
}
