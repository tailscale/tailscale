// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
)

var routeTableCmd = &ffcli.Command{
	Name:       "route-table",
	ShortUsage: "tailscale route-table",
	ShortHelp:  "Show the IP routing table",
	LongHelp:   "Show the IP routing table",
	Exec:       showRouteTable,
}

type routeEntry struct {
	prefix  string
	nextHop string
}

func showRouteTable(ctx context.Context, args []string) error {
	var localClient = tailscale.LocalClient{
		Socket: paths.DefaultTailscaledSocket(),
	}
	tailscaleStatus, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}

	routes := collectRoutes(tailscaleStatus)
	printRouteTable(routes)
	return nil
}

func collectRoutes(status *ipnstate.Status) []routeEntry {
	var routes []routeEntry

	for _, peer := range status.Peer {
		if peer.TailscaleIPs == nil || len(peer.TailscaleIPs) == 0 {
			continue
		}
		nextHop := peer.TailscaleIPs[0].String()

		if peer.AllowedIPs != nil {
			for i := 0; i < peer.AllowedIPs.Len(); i++ {
				prefix := peer.AllowedIPs.At(i).String()
				routes = append(routes, routeEntry{
					prefix:  prefix,
					nextHop: nextHop,
				})
			}
		}
	}

	// Sort routes for consistent output
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].prefix < routes[j].prefix
	})

	return routes
}

func printRouteTable(routes []routeEntry) {
	fmt.Println("Tailscale IP Routing Table")
	fmt.Println("Codes: T - Tailscale")
	fmt.Println()

	for _, route := range routes {
		prefix := strings.Split(route.prefix, "/")
		network := prefix[0]
		mask := prefix[1]

		fmt.Printf("T    %s [1/0] via %s\n", network, route.nextHop)
		fmt.Printf("         %s/%s\n", network, mask)
	}
}
