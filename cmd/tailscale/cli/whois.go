// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var whoisCmd = &ffcli.Command{
	Name:       "whois",
	ShortUsage: "tailscale whois [--json] ip[:port]",
	ShortHelp:  "Show the machine and user associated with a Tailscale IP (v4 or v6)",
	LongHelp: strings.TrimSpace(`
	'tailscale whois' shows the machine and user associated with a Tailscale IP (v4 or v6).
	`),
	Exec: runWhoIs,
	FlagSet: func() *flag.FlagSet {
		fs := newFlagSet("whois")
		fs.BoolVar(&whoIsArgs.json, "json", false, "output in JSON format")
		fs.StringVar(&whoIsArgs.proto, "proto", "", `protocol; one of "tcp" or "udp"; empty mans both `)
		return fs
	}(),
}

var whoIsArgs struct {
	json  bool   // output in JSON format
	proto string // "tcp" or "udp"
}

func runWhoIs(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return errors.New("too many arguments, expected at most one peer")
	} else if len(args) == 0 {
		return errors.New("missing argument, expected one peer")
	}
	who, err := localClient.WhoIsProto(ctx, whoIsArgs.proto, args[0])
	if err != nil {
		return err
	}
	if whoIsArgs.json {
		ec := json.NewEncoder(Stdout)
		ec.SetIndent("", "  ")
		ec.Encode(who)
		return nil
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	fmt.Fprintf(w, "Machine:\n")
	fmt.Fprintf(w, "  Name:\t%s\n", strings.TrimSuffix(who.Node.Name, "."))
	fmt.Fprintf(w, "  ID:\t%s\n", who.Node.StableID)
	fmt.Fprintf(w, "  Addresses:\t%s\n", who.Node.Addresses)
	if len(who.Node.AllowedIPs) > 2 {
		fmt.Fprintf(w, "  AllowedIPs:\t%s\n", who.Node.AllowedIPs[2:])
	}
	if who.Node.IsTagged() {
		fmt.Fprintf(w, "  Tags:\t%s\n", strings.Join(who.Node.Tags, ", "))
	} else {
		fmt.Fprintln(w, "User:")
		fmt.Fprintf(w, "  Name:\t%s\n", who.UserProfile.LoginName)
		fmt.Fprintf(w, "  ID:\t%d\n", who.UserProfile.ID)
	}
	w.Flush()
	w = nil // avoid accidental use

	if cm := who.CapMap; len(cm) > 0 {
		printf("Capabilities:\n")
		for cap, vals := range cm {
			// To make the output more readable, we have to reindent the JSON
			// values so they line up with the cap name.
			if len(vals) > 0 {
				v, _ := json.MarshalIndent(vals, "      ", "  ")

				printf("  - %s:\n", cap)
				printf("      %s\n", v)
			} else {
				printf("  - %s\n", cap)
			}
		}
	}
	return nil
}
