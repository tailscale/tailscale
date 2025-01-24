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
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/ipn"
)

var switchCmd = &ffcli.Command{
	Name:       "switch",
	ShortUsage: "tailscale switch <id>",
	ShortHelp:  "Switch to a different Tailscale account",
	LongHelp: `"tailscale switch" switches between logged in accounts. You can
use the ID that's returned from 'tailnet switch -list'
to pick which profile you want to switch to. Alternatively, you
can use the Tailnet or the account names to switch as well.

This command is currently in alpha and may change in the future.`,

	FlagSet: func() *flag.FlagSet {
		fs := flag.NewFlagSet("switch", flag.ExitOnError)
		fs.BoolVar(&switchArgs.list, "list", false, "list available accounts")
		return fs
	}(),
	Exec: switchProfile,
}

func init() {
	ffcomplete.Args(switchCmd, func(s []string) (words []string, dir ffcomplete.ShellCompDirective, err error) {
		_, all, err := localClient.ProfileStatus(context.Background())
		if err != nil {
			return nil, 0, err
		}

		seen := make(map[string]bool, 3*len(all))
		wordfns := []func(prof ipn.LoginProfile) string{
			func(prof ipn.LoginProfile) string { return string(prof.ID) },
			func(prof ipn.LoginProfile) string { return prof.NetworkProfile.DomainName },
			func(prof ipn.LoginProfile) string { return prof.Name },
		}

		for _, wordfn := range wordfns {
			for _, prof := range all {
				word := wordfn(prof)
				if seen[word] {
					continue
				}
				seen[word] = true
				words = append(words, fmt.Sprintf("%s\tid: %s, tailnet: %s, account: %s", word, prof.ID, prof.NetworkProfile.DomainName, prof.Name))
			}
		}
		return words, ffcomplete.ShellCompDirectiveNoFileComp, nil
	})
}

var switchArgs struct {
	list bool
}

func listProfiles(ctx context.Context) error {
	curP, all, err := localClient.ProfileStatus(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(Stdout, 2, 2, 2, ' ', 0)
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
