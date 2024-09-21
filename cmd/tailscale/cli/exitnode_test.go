// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestFilterFormatAndSortExitNodes(t *testing.T) {
	t.Run("without filter", func(t *testing.T) {
		ps := []*ipnstate.PeerStatus{
			{
				HostName: "everest-1",
				Location: &tailcfg.Location{
					Country:     "Everest",
					CountryCode: "evr",
					City:        "Hillary",
					CityCode:    "hil",
					Priority:    100,
				},
			},
			{
				HostName: "lhotse-1",
				Location: &tailcfg.Location{
					Country:     "Lhotse",
					CountryCode: "lho",
					City:        "Fritz",
					CityCode:    "fri",
					Priority:    200,
				},
			},
			{
				HostName: "lhotse-2",
				Location: &tailcfg.Location{
					Country:     "Lhotse",
					CountryCode: "lho",
					City:        "Fritz",
					CityCode:    "fri",
					Priority:    100,
				},
			},
			{
				HostName: "nuptse-1",
				Location: &tailcfg.Location{
					Country:     "Nuptse",
					CountryCode: "nup",
					City:        "Walmsley",
					CityCode:    "wal",
					Priority:    200,
				},
			},
			{
				HostName: "nuptse-2",
				Location: &tailcfg.Location{
					Country:     "Nuptse",
					CountryCode: "nup",
					City:        "Bonington",
					CityCode:    "bon",
					Priority:    10,
				},
			},
			{
				HostName: "Makalu",
			},
		}

		want := filteredExitNodes{
			Countries: []*filteredCountry{
				{
					Name: noLocationData,
					Cities: []*filteredCity{
						{
							Name: noLocationData,
							Peers: []*ipnstate.PeerStatus{
								ps[5],
							},
						},
					},
				},
				{
					Name: "Everest",
					Cities: []*filteredCity{
						{
							Name: "Hillary",
							Peers: []*ipnstate.PeerStatus{
								ps[0],
							},
						},
					},
				},
				{
					Name: "Lhotse",
					Cities: []*filteredCity{
						{
							Name: "Fritz",
							Peers: []*ipnstate.PeerStatus{
								ps[1],
							},
						},
					},
				},
				{
					Name: "Nuptse",
					Cities: []*filteredCity{
						{
							Name: "Any",
							Peers: []*ipnstate.PeerStatus{
								ps[3],
							},
						},
						{
							Name: "Bonington",
							Peers: []*ipnstate.PeerStatus{
								ps[4],
							},
						},
						{
							Name: "Walmsley",
							Peers: []*ipnstate.PeerStatus{
								ps[3],
							},
						},
					},
				},
			},
		}

		result := filterFormatAndSortExitNodes(ps, "")

		if res := cmp.Diff(result.Countries, want.Countries, cmpopts.IgnoreUnexported(key.NodePublic{})); res != "" {
			t.Fatal(res)
		}
	})

	t.Run("with country filter", func(t *testing.T) {
		ps := []*ipnstate.PeerStatus{
			{
				HostName: "baker-1",
				Location: &tailcfg.Location{
					Country:     "Pacific",
					CountryCode: "pst",
					City:        "Baker",
					CityCode:    "col",
					Priority:    100,
				},
			},
			{
				HostName: "hood-1",
				Location: &tailcfg.Location{
					Country:     "Pacific",
					CountryCode: "pst",
					City:        "Hood",
					CityCode:    "hoo",
					Priority:    500,
				},
			},
			{
				HostName: "rainier-1",
				Location: &tailcfg.Location{
					Country:     "Pacific",
					CountryCode: "pst",
					City:        "Rainier",
					CityCode:    "rai",
					Priority:    100,
				},
			},
			{
				HostName: "rainier-2",
				Location: &tailcfg.Location{
					Country:     "Pacific",
					CountryCode: "pst",
					City:        "Rainier",
					CityCode:    "rai",
					Priority:    10,
				},
			},
			{
				HostName: "mitchell-1",
				Location: &tailcfg.Location{
					Country:     "Atlantic",
					CountryCode: "atl",
					City:        "Mitchell",
					CityCode:    "mit",
					Priority:    200,
				},
			},
		}

		want := filteredExitNodes{
			Countries: []*filteredCountry{
				{
					Name: "Pacific",
					Cities: []*filteredCity{
						{
							Name: "Any",
							Peers: []*ipnstate.PeerStatus{
								ps[1],
							},
						},
						{
							Name: "Baker",
							Peers: []*ipnstate.PeerStatus{
								ps[0],
							},
						},
						{
							Name: "Hood",
							Peers: []*ipnstate.PeerStatus{
								ps[1],
							},
						},
						{
							Name: "Rainier",
							Peers: []*ipnstate.PeerStatus{
								ps[2], ps[3],
							},
						},
					},
				},
			},
		}

		result := filterFormatAndSortExitNodes(ps, "Pacific")

		if res := cmp.Diff(result.Countries, want.Countries, cmpopts.IgnoreUnexported(key.NodePublic{})); res != "" {
			t.Fatal(res)
		}
	})
}

func TestSortPeersByPriority(t *testing.T) {
	ps := []*ipnstate.PeerStatus{
		{
			Location: &tailcfg.Location{
				Priority: 100,
			},
		},
		{
			Location: &tailcfg.Location{
				Priority: 200,
			},
		},
		{
			Location: &tailcfg.Location{
				Priority: 300,
			},
		},
	}

	sortPeersByPriority(ps)

	if ps[0].Location.Priority != 300 {
		t.Fatalf("sortPeersByPriority did not order PeerStatus with highest priority as index 0, got %v, want %v", ps[0].Location.Priority, 300)
	}
}

func TestSortByCountryName(t *testing.T) {
	fc := []*filteredCountry{
		{
			Name: "Albania",
		},
		{
			Name: "Sweden",
		},
		{
			Name: "Zimbabwe",
		},
		{
			Name: noLocationData,
		},
	}

	sortByCountryName(fc)

	if fc[0].Name != noLocationData {
		t.Fatalf("sortByCountryName did not order countries by alphabetical order, got %v, want %v", fc[0].Name, noLocationData)
	}
}

func TestSortByCityName(t *testing.T) {
	fc := []*filteredCity{
		{
			Name: "Kingston",
		},
		{
			Name: "Goteborg",
		},
		{
			Name: "Squamish",
		},
		{
			Name: noLocationData,
		},
	}

	sortByCityName(fc)

	if fc[0].Name != noLocationData {
		t.Fatalf("sortByCityName did not order cities by alphabetical order, got %v, want %v", fc[0].Name, noLocationData)
	}
}
