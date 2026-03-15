// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tailcfg"
)

func serviceCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "service",
		ShortUsage: "tailscale service <subcommand> [flags]",
		ShortHelp:  "Manage and inspect Tailscale VIP services",
		Subcommands: []*ffcli.Command{
			{
				Name:       "list",
				ShortUsage: "tailscale service list [--json]",
				ShortHelp:  "List VIP services approved for this node",
				LongHelp: strings.TrimSpace(`
The 'tailscale service list' command shows the VIP services that the control
plane has approved this node to serve, including their assigned IP addresses,
accepted ports, and any application-specific annotations.
`),
				Exec: runServiceList,
				FlagSet: (func() *flag.FlagSet {
					fs := newFlagSet("list")
					fs.BoolVar(&serviceArgs.json, "json", false, "output in JSON format")
					return fs
				})(),
			},
		},
	}
}

var serviceArgs struct {
	json bool
}

func runServiceList(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale service list'")
	}
	details, err := localClient.GetServiceDetails(ctx)
	if err != nil {
		return err
	}
	if serviceArgs.json {
		enc := json.NewEncoder(Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(details)
		return nil
	}
	if len(details) == 0 {
		printf("No VIP services configured for this node.\n")
		return nil
	}
	printServiceDetails(details)
	return nil
}

func printServiceDetails(details []*tailcfg.ServiceDetail) {
	w := tabwriter.NewWriter(Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRS\tPORTS\t")
	fmt.Fprintln(w, "----\t-----\t-----\t")
	for _, svc := range details {
		addrs := make([]string, len(svc.Addrs))
		for i, a := range svc.Addrs {
			addrs[i] = a.String()
		}
		ports := make([]string, len(svc.Ports))
		for i, p := range svc.Ports {
			ports[i] = p.String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t\n",
			svc.Name,
			strings.Join(addrs, ", "),
			strings.Join(ports, ", "),
		)
		if len(svc.Annotations) > 0 {
			// Print annotations sorted by key, indented under the service row.
			keys := make([]string, 0, len(svc.Annotations))
			for k := range svc.Annotations {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(w, "  %s: %s\t\t\t\n", k, svc.Annotations[k])
			}
		}
	}
	w.Flush()
}
