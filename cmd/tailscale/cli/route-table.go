// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
)

var routeTableArgs struct {
	includeTailnetIPs bool
}

var routeTableCmd = &ffcli.Command{
	Name:       "route-table",
	ShortUsage: "tailscale route-table [--tailnet-ips]",
	ShortHelp:  "Show the IP routing table",
	LongHelp:   "Show the IP routing table. Use --tailnet-ips to include Tailscale node IPs.",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("route-table", flag.ExitOnError)
		fs.BoolVar(&routeTableArgs.includeTailnetIPs, "tailnet-ips", false, "include Tailscale node IPs in the output")
		return fs
	})(),
	Exec: showRouteTable,
}

type routeEntry struct {
	prefix      string
	nextHopIP   string
	nextHopName string
}

func showRouteTable(ctx context.Context, args []string) error {
	var localClient = tailscale.LocalClient{
		Socket: paths.DefaultTailscaledSocket(),
	}
	tailscaleStatus, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}

	routes := collectRoutes(tailscaleStatus, routeTableArgs.includeTailnetIPs)
	printRouteTable(routes)
	return nil
}

func collectRoutes(status *ipnstate.Status, includeTailnetIPs bool) []routeEntry {
	var routes []routeEntry

	for _, peer := range status.Peer {
		if peer.TailscaleIPs == nil || len(peer.TailscaleIPs) == 0 {
			continue
		}
		nextHopIP := peer.TailscaleIPs[0].String()
		nextHopName := peer.HostName

		if peer.AllowedIPs != nil {
			for i := 0; i < peer.AllowedIPs.Len(); i++ {
				prefix := peer.AllowedIPs.At(i)
				if !includeTailnetIPs && isTailscaleNodeIP(prefix, peer.TailscaleIPs) {
					continue
				}
				routes = append(routes, routeEntry{
					prefix:      prefix.String(),
					nextHopIP:   nextHopIP,
					nextHopName: nextHopName,
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

func isTailscaleNodeIP(prefix netip.Prefix, tailscaleIPs []netip.Addr) bool {
	for _, ip := range tailscaleIPs {
		if prefix.Bits() == ip.BitLen() && prefix.Addr() == ip {
			return true
		}
	}
	return false
}

func printRouteTable(routes []routeEntry) {
	fmt.Println("Tailscale IP Routing Table")
	fmt.Println("Codes: T - Tailscale")
	fmt.Println()

	for _, route := range routes {
		prefix := strings.Split(route.prefix, "/")
		network := prefix[0]
		mask := prefix[1]

		fmt.Printf("T    %s/%s via %s (%s)\n", network, mask, route.nextHopIP, route.nextHopName)
	}
}
