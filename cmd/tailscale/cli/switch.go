// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

var switchCmd = &ffcli.Command{
	Name:      "switch",
	ShortHelp: "Switches to a different Tailscale account",
	FlagSet: func() *flag.FlagSet {
		fs := flag.NewFlagSet("switch", flag.ExitOnError)
		fs.BoolVar(&switchArgs.list, "list", false, "list available accounts")
		return fs
	}(),
	Exec: switchProfile,
	UsageFunc: func(*ffcli.Command) string {
		return `USAGE
  switch <id>
  switch --list

"tailscale switch" switches between logged in accounts. You can
use the ID that's returned from 'tailnet switch -list'
to pick which profile you want to switch to. Alternatively, you
can use the Tailnet or the account names to switch as well.

This command is currently in alpha and may change in the future.`
	},
}

var switchArgs struct {
	list bool
}

func listProfiles(ctx context.Context) error {
	curP, all, err := localClient.ProfileStatus(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
	defer tw.Flush()
	printRow := func(vals ...string) {
		fmt.Fprintln(tw, strings.Join(vals, "\t"))
	}
	printRow("ID", "Tailnet", "Account")
	for _, prof := range all {
		name := prof.Name
		if prof.ID == curP.ID {
			name += "*"
		}
		printRow(
			string(prof.ID),
			prof.NetworkProfile.DomainName,
			name,
		)
	}
	return nil
}

func switchProfile(ctx context.Context, args []string) error {
	if switchArgs.list {
		return listProfiles(ctx)
	}
	if len(args) != 1 {
		outln("usage: tailscale switch NAME")
		os.Exit(1)
	}
	cp, all, err := localClient.ProfileStatus(ctx)
	if err != nil {
		errf("Failed to switch to account: %v\n", err)
		os.Exit(1)
	}
	var profID ipn.ProfileID
	// Allow matching by ID, Tailnet, or Account
	// in that order.
	for _, p := range all {
		if p.ID == ipn.ProfileID(args[0]) {
			profID = p.ID
			break
		}
	}
	if profID == "" {
		for _, p := range all {
			if p.NetworkProfile.DomainName == args[0] {
				profID = p.ID
				break
			}
		}
	}
	if profID == "" {
		for _, p := range all {
			if p.Name == args[0] {
				profID = p.ID
				break
			}
		}
	}
	if profID == "" {
		errf("No profile named %q\n", args[0])
		os.Exit(1)
	}
	if profID == cp.ID {
		printf("Already on account %q\n", args[0])
		os.Exit(0)
	}
	if err := localClient.SwitchProfile(ctx, profID); err != nil {
		errf("Failed to switch to account: %v\n", err)
		os.Exit(1)
	}
	printf("Switching to account %q\n", args[0])
	for {
		select {
		case <-ctx.Done():
			errf("Timed out waiting for switch to complete.")
			os.Exit(1)
		default:
		}
		st, err := localClient.StatusWithoutPeers(ctx)
		if err != nil {
			errf("Error getting status: %v", err)
			os.Exit(1)
		}
		switch st.BackendState {
		case "NoState", "Starting":
			// TODO(maisem): maybe add a way to subscribe to state changes to
			// LocalClient.
			time.Sleep(100 * time.Millisecond)
			continue
		case "NeedsLogin":
			outln("Logged out.")
			outln("To log in, run:")
			outln("  tailscale up")
			return nil
		case "Running":
			outln("Success.")
			return nil
		}
		// For all other states, use the default error message.
		if msg, ok := isRunningOrStarting(st); !ok {
			outln(msg)
			os.Exit(1)
		}
	}
}
