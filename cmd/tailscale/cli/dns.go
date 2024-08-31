// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var dnsCmd = &ffcli.Command{
	Name:       "dns",
	ShortHelp:  "Diagnose the internal DNS forwarder",
	LongHelp:   dnsCmdLongHelp(),
	ShortUsage: "tailscale dns <subcommand> [flags]",
	UsageFunc:  usageFuncNoDefaultValues,
	Subcommands: []*ffcli.Command{
		{
			Name:       "status",
			ShortUsage: "tailscale dns status [--all]",
			Exec:       runDNSStatus,
			ShortHelp:  "Prints the current DNS status and configuration",
			LongHelp:   dnsStatusLongHelp(),
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("status")
				fs.BoolVar(&dnsStatusArgs.all, "all", false, "outputs advanced debugging information (fallback resolvers, nameservers, cert domains, extra records, and exit node filtered set)")
				return fs
			})(),
		},

		// TODO: implement `tailscale query` here

		// TODO: implement `tailscale log` here

		// The above work is tracked in https://github.com/tailscale/tailscale/issues/13326
	},
}

func dnsCmdLongHelp() string {
	return `The 'tailscale dns' subcommand provides tools for diagnosing the internal DNS forwarder (100.100.100.100).
	
For more information about the DNS functionality built into Tailscale, refer to https://tailscale.com/kb/1054/dns.`
}
