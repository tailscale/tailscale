// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

var debugEnableServiceCommands = envknob.RegisterBool("TS_DEBUG_ENABLE_SERVICE_COMMANDS")

const serviceListUsage = "tailscale service list"

func serviceCmd() *ffcli.Command {
	// The service commands are still in development and gated behind a debug
	// env knob. When unset, serviceCmd returns nil and is filtered out of the
	// root command's subcommands by nonNilCmds.
	if !debugEnableServiceCommands() {
		return nil
	}
	return &ffcli.Command{
		Name:       "service",
		ShortHelp:  "Interact with Tailscale Services",
		ShortUsage: "tailscale service",
		LongHelp: strings.TrimSpace(`
The 'tailscale service' command groups subcommands for Tailscale Services.

A Tailscale Service is a virtual service with its own IP addresses. Which
Services this node can reach is determined by the tailnet's ACLs. Use the 'list'
subcommand to see the Services currently available to this node.
`),
		UsageFunc: usageFuncNoDefaultValues,
		Exec:      func(context.Context, []string) error { return flag.ErrHelp },
		Subcommands: []*ffcli.Command{
			{
				Name:       "list",
				ShortUsage: serviceListUsage,
				ShortHelp:  "List the Tailscale Services your node can access",
				Exec:       runServiceList,
				FlagSet: func() *flag.FlagSet {
					fs := newFlagSet("list")
					fs.BoolVar(&serviceListArgs.json, "json", false, "output in JSON format")
					return fs
				}(),
			},
		},
	}
}

var serviceListArgs struct {
	json bool
}

// serviceListEntry decorates a [tailcfg.ServiceDetails] with the Service's
// MagicDNS name, both for the table's DNS Name column and so the name is
// included in the JSON output.
type serviceListEntry struct {
	tailcfg.ServiceDetails
	DNSName string
}

// runServiceList is the entry point for the "tailscale service list" command.
func runServiceList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: %s", serviceListUsage)
	}

	lc := localClientFromContext(ctx)

	services, err := lc.GetServices(ctx)
	if err != nil {
		return err
	}

	// We need the tailnet's MagicDNS suffix to build each Service's DNS name.
	st, err := lc.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	var magicDNSSuffix string
	if st.CurrentTailnet != nil {
		magicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}

	// Sort the services by name for stable output.
	names := make([]tailcfg.ServiceName, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	slices.Sort(names)

	entries := make([]serviceListEntry, 0, len(names))
	for _, name := range names {
		svc := services[name]
		entries = append(entries, serviceListEntry{
			ServiceDetails: svc,
			DNSName:        serviceDNSName(name, magicDNSSuffix),
		})
	}

	if serviceListArgs.json {
		enc := json.NewEncoder(Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	if len(entries) == 0 {
		fmt.Fprintln(Stdout, "No Tailscale Services are available to this node.")
		return nil
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t", "NAME", "DISPLAY NAME", "DNS NAME", "IP", "ENDPOINTS")
	for _, e := range entries {
		// Show a single IP, always the first in Addrs. If a tailnet has IPv4
		// disabled, the netmap only includes the v6 address, so the 0th index
		// is the v6 address and that's what we show.
		var ip string
		if len(e.Addrs) > 0 {
			ip = e.Addrs[0].String()
		}
		fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t",
			e.Name,
			cmp.Or(e.DisplayName, "-"),
			cmp.Or(e.DNSName, "-"),
			cmp.Or(ip, "-"),
			joinStringers(e.Ports, "-"),
		)
	}
	fmt.Fprintln(w)
	return nil
}

// serviceDNSName returns the MagicDNS name for a Service, of the form
// "<name>.<magicDNSSuffix>". It returns "" if the name or suffix is missing.
func serviceDNSName(name tailcfg.ServiceName, magicDNSSuffix string) string {
	bare := name.WithoutPrefix()
	if bare == "" || magicDNSSuffix == "" {
		return ""
	}
	return bare + "." + strings.Trim(magicDNSSuffix, ".")
}

// joinStringers renders a slice of fmt.Stringer-like values as a
// comma-separated string, returning empty if the slice is empty.
func joinStringers[T fmt.Stringer](vals []T, empty string) string {
	if len(vals) == 0 {
		return empty
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = v.String()
	}
	return strings.Join(strs, ", ")
}
