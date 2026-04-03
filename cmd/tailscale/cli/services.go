// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func servicesCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "service",
		ShortUsage: "tailscale service <subcommand>",
		ShortHelp:  "Manage and view VIP services on your tailnet",
		Subcommands: []*ffcli.Command{
			{
				Name:       "list",
				ShortUsage: "tailscale service list",
				ShortHelp:  "List VIP services visible to this node",
				Exec:       runServicesList,
			},
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

func runServicesList(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale service list'")
	}
	services, err := localClient.GetServices(ctx)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return errors.New("no services found")
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\n %s\t%s\t%s\t", "SERVICE", "ADDRS", "PORTS")
	for _, svc := range services {
		addrs := make([]string, len(svc.Addrs))
		for i, a := range svc.Addrs {
			addrs[i] = a.String()
		}
		ports := make([]string, len(svc.Ports))
		for i, p := range svc.Ports {
			ports[i] = p.String()
		}
		fmt.Fprintf(w, "\n %s\t%s\t%s\t",
			svc.Name,
			strings.Join(addrs, ", "),
			strings.Join(ports, ", "),
		)
	}
	fmt.Fprintln(w)
	return nil
}
