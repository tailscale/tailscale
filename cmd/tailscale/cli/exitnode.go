// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	xmaps "golang.org/x/exp/maps"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func exitNodeCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "exit-node",
		ShortUsage: "exit-node [flags]",
		ShortHelp:  "Show machines on your tailnet configured as exit nodes",
		LongHelp:   "Show machines on your tailnet configured as exit nodes",
		Exec: func(context.Context, []string) error {
			return errors.New("exit-node subcommand required; run 'tailscale exit-node -h' for details")
		},
		Subcommands: append([]*ffcli.Command{
			{
				Name:       "list",
				ShortUsage: "exit-node list [flags]",
				ShortHelp:  "Show exit nodes",
				Exec:       runExitNodeList,
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("list")
					fs.StringVar(&exitNodeArgs.filter, "filter", "", "filter exit nodes by country")
					return fs
				})(),
			}},
			(func() []*ffcli.Command {
				if !envknob.UseWIPCode() {
					return nil
				}
				return []*ffcli.Command{
					{
						Name:       "connect",
						ShortUsage: "exit-node connect",
						ShortHelp:  "connect to most recently used exit node",
						Exec:       exitNodeSetUse(true),
					},
					{
						Name:       "disconnect",
						ShortUsage: "exit-node disconnect",
						ShortHelp:  "disconnect from current exit node, if any",
						Exec:       exitNodeSetUse(false),
					},
				}
			})()...),
	}
}

var exitNodeArgs struct {
	filter string
}

func exitNodeSetUse(wantOn bool) func(ctx context.Context, args []string) error {
	return func(ctx context.Context, args []string) error {
		if len(args) > 0 {
			return errors.New("unexpected non-flag arguments")
		}
		err := localClient.SetUseExitNode(ctx, wantOn)
		if err != nil {
			if !wantOn {
				pref, err := localClient.GetPrefs(ctx)
				if err == nil && pref.ExitNodeID == "" {
					// Two processes concurrently turned it off.
					return nil
				}
			}
		}
		return err
	}
}

// runExitNodeList returns a formatted list of exit nodes for a tailnet.
// If the exit node has location and priority data, only the highest
// priority node for each city location is shown to the user.
// If the country location has more than one city, an 'Any' city
// is returned for the country, which lists the highest priority
// node in that country.
// For countries without location data, each exit node is displayed.
func runExitNodeList(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale exit-node list'")
	}
	getStatus := localClient.Status
	st, err := getStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}

	var peers []*ipnstate.PeerStatus
	for _, ps := range st.Peer {
		if !ps.ExitNodeOption {
			// We only show exit nodes under the exit-node subcommand.
			continue
		}
		peers = append(peers, ps)
	}

	if len(peers) == 0 {
		return errors.New("no exit nodes found")
	}

	filteredPeers := filterFormatAndSortExitNodes(peers, exitNodeArgs.filter)

	if len(filteredPeers.Countries) == 0 && exitNodeArgs.filter != "" {
		return fmt.Errorf("no exit nodes found for %q", exitNodeArgs.filter)
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t", "IP", "HOSTNAME", "COUNTRY", "CITY", "STATUS")
	for _, country := range filteredPeers.Countries {
		for _, city := range country.Cities {
			for _, peer := range city.Peers {
				fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t", peer.TailscaleIPs[0], strings.Trim(peer.DNSName, "."), country.Name, city.Name, peerStatus(peer))
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# To use an exit node, use `tailscale set --exit-node=` followed by the hostname or IP")

	return nil
}

// peerStatus returns a string representing the current state of
// a peer. If there is no notable state, a - is returned.
func peerStatus(peer *ipnstate.PeerStatus) string {
	if !peer.Active {
		if peer.ExitNode {
			return "selected but offline"
		}
		if !peer.Online {
			return "offline"
		}
	}

	if peer.ExitNode {
		return "selected"
	}

	return "-"
}

type filteredExitNodes struct {
	Countries []*filteredCountry
}

type filteredCountry struct {
	Name   string
	Cities []*filteredCity
}

type filteredCity struct {
	Name  string
	Peers []*ipnstate.PeerStatus
}

const noLocationData = "-"

var noLocation = &tailcfg.Location{
	Country:     noLocationData,
	CountryCode: noLocationData,
	City:        noLocationData,
	CityCode:    noLocationData,
}

// filterFormatAndSortExitNodes filters and sorts exit nodes into
// alphabetical order, by country, city and then by priority if
// present.
// If an exit node has location data, and the country has more than
// one city, an `Any` city is added to the country that contains the
// highest priority exit node within that country.
// For exit nodes without location data, their country fields are
// defined as '-' to indicate that the data is not available.
func filterFormatAndSortExitNodes(peers []*ipnstate.PeerStatus, filterBy string) filteredExitNodes {
	// first get peers into some fixed order, as code below doesn't break ties
	// and our input comes from a random range-over-map.
	slices.SortFunc(peers, func(a, b *ipnstate.PeerStatus) int {
		return strings.Compare(a.DNSName, b.DNSName)
	})

	countries := make(map[string]*filteredCountry)
	cities := make(map[string]*filteredCity)
	for _, ps := range peers {
		loc := cmp.Or(ps.Location, noLocation)

		if filterBy != "" && loc.Country != filterBy {
			continue
		}

		co, ok := countries[loc.CountryCode]
		if !ok {
			co = &filteredCountry{
				Name: loc.Country,
			}
			countries[loc.CountryCode] = co
		}

		ci, ok := cities[loc.CityCode]
		if !ok {
			ci = &filteredCity{
				Name: loc.City,
			}
			cities[loc.CityCode] = ci
			co.Cities = append(co.Cities, ci)
		}
		ci.Peers = append(ci.Peers, ps)
	}

	filteredExitNodes := filteredExitNodes{
		Countries: xmaps.Values(countries),
	}

	for _, country := range filteredExitNodes.Countries {
		if country.Name == noLocationData {
			// Countries without location data should not
			// be filtered further.
			continue
		}

		var countryAnyPeer []*ipnstate.PeerStatus
		for _, city := range country.Cities {
			sortPeersByPriority(city.Peers)
			countryAnyPeer = append(countryAnyPeer, city.Peers...)
			var reducedCityPeers []*ipnstate.PeerStatus
			for i, peer := range city.Peers {
				if i == 0 || peer.ExitNode {
					// We only return the highest priority peer and any peer that
					// is currently the active exit node.
					reducedCityPeers = append(reducedCityPeers, peer)
				}
			}
			city.Peers = reducedCityPeers
		}
		sortByCityName(country.Cities)
		sortPeersByPriority(countryAnyPeer)

		if len(country.Cities) > 1 {
			// For countries with more than one city, we want to return the
			// option of the best peer for that country.
			country.Cities = append([]*filteredCity{
				{
					Name:  "Any",
					Peers: []*ipnstate.PeerStatus{countryAnyPeer[0]},
				},
			}, country.Cities...)
		}
	}
	sortByCountryName(filteredExitNodes.Countries)

	return filteredExitNodes
}

// sortPeersByPriority sorts a slice of PeerStatus
// by location.Priority, in order of highest priority.
func sortPeersByPriority(peers []*ipnstate.PeerStatus) {
	slices.SortStableFunc(peers, func(a, b *ipnstate.PeerStatus) int {
		return cmp.Compare(b.Location.Priority, a.Location.Priority)
	})
}

// sortByCityName sorts a slice of filteredCity alphabetically
// by name. The '-' used to indicate no location data will always
// be sorted to the front of the slice.
func sortByCityName(cities []*filteredCity) {
	slices.SortStableFunc(cities, func(a, b *filteredCity) int { return strings.Compare(a.Name, b.Name) })
}

// sortByCountryName sorts a slice of filteredCountry alphabetically
// by name. The '-' used to indicate no location data will always
// be sorted to the front of the slice.
func sortByCountryName(countries []*filteredCountry) {
	slices.SortStableFunc(countries, func(a, b *filteredCountry) int { return strings.Compare(a.Name, b.Name) })
}
