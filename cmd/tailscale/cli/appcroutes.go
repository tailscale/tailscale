// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/types/appctype"
)

var appcRoutesArgs struct {
	all       bool
	domainMap bool
	n         bool
}

var appcRoutesCmd = &ffcli.Command{
	Name:       "appc-routes",
	ShortUsage: "tailscale appc-routes",
	Exec:       runAppcRoutesInfo,
	ShortHelp:  "Print the current app connector routes",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("appc-routes")
		fs.BoolVar(&appcRoutesArgs.all, "all", false, "Print learned domains and routes and extra policy configured routes.")
		fs.BoolVar(&appcRoutesArgs.domainMap, "map", false, "Print the map of learned domains: [routes].")
		fs.BoolVar(&appcRoutesArgs.n, "n", false, "Print the total number of routes this node advertises.")
		return fs
	})(),
	LongHelp: strings.TrimSpace(`
The 'tailscale appc-routes' command prints the current App Connector route status.

By default this command prints the domains configured in the app connector configuration and how many routes have been
learned for each domain.

--all prints the routes learned from the domains configured in the app connector configuration; and any extra routes provided
in the the policy app connector 'routes' field.

--map prints the routes learned from the domains configured in the app connector configuration.

-n prints the total number of routes advertised by this device, whether learned, set in the policy, or set locally.

For more information about App Connectors, refer to
https://tailscale.com/kb/1281/app-connectors
`),
}

func getAllOutput(ri *appctype.RouteInfo) (string, error) {
	domains, err := json.MarshalIndent(ri.Domains, " ", "  ")
	if err != nil {
		return "", err
	}
	control, err := json.MarshalIndent(ri.Control, " ", "  ")
	if err != nil {
		return "", err
	}
	s := fmt.Sprintf(`Learned Routes
==============
%s

Routes from Policy
==================
%s
`, domains, control)
	return s, nil
}

type domainCount struct {
	domain string
	count  int
}

func getSummarizeLearnedOutput(ri *appctype.RouteInfo) string {
	x := make([]domainCount, len(ri.Domains))
	i := 0
	maxDomainWidth := 0
	for k, v := range ri.Domains {
		if len(k) > maxDomainWidth {
			maxDomainWidth = len(k)
		}
		x[i] = domainCount{domain: k, count: len(v)}
		i++
	}
	slices.SortFunc(x, func(i, j domainCount) int {
		if i.count > j.count {
			return -1
		}
		if i.count < j.count {
			return 1
		}
		if i.domain > j.domain {
			return 1
		}
		if i.domain < j.domain {
			return -1
		}
		return 0
	})
	s := ""
	fmtString := fmt.Sprintf("%%-%ds %%d\n", maxDomainWidth) // eg "%-10s %d\n"
	for _, dc := range x {
		s += fmt.Sprintf(fmtString, dc.domain, dc.count)
	}
	return s
}

func runAppcRoutesInfo(ctx context.Context, args []string) error {
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	if !prefs.AppConnector.Advertise {
		fmt.Println("not a connector")
		return nil
	}

	if appcRoutesArgs.n {
		fmt.Println(len(prefs.AdvertiseRoutes))
		return nil
	}

	routeInfo, err := localClient.GetAppConnectorRouteInfo(ctx)
	if err != nil {
		return err
	}

	if appcRoutesArgs.domainMap {
		domains, err := json.Marshal(routeInfo.Domains)
		if err != nil {
			return err
		}
		fmt.Println(string(domains))
		return nil
	}

	if appcRoutesArgs.all {
		s, err := getAllOutput(&routeInfo)
		if err != nil {
			return err
		}
		fmt.Println(s)
		return nil
	}

	fmt.Print(getSummarizeLearnedOutput(&routeInfo))
	return nil
}
