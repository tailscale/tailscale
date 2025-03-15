// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/ipn"
)

var removeCmd = &ffcli.Command{
	Name:       "remove",
	ShortUsage: "tailscale remove <id>",
	ShortHelp:  "Remove a Tailscale account",
	LongHelp: `"tailscale remove" removes a logged in account. You can
use the ID that's returned from 'tailnet remove -list'
to pick which profile you want to remove. Alternatively, you
can use the Tailnet or the account names to remove as well.

This command works similarly to 'tailscale switch' but is used to remove accounts.`,

	FlagSet: func() *flag.FlagSet {
		fs := flag.NewFlagSet("remove", flag.ExitOnError)
		fs.BoolVar(&removeArgs.list, "list", false, "list available accounts")
		return fs
	}(),
	Exec: removeProfile,
}

func init() {
	ffcomplete.Args(removeCmd, func(s []string) (words []string, dir ffcomplete.ShellCompDirective, err error) {
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

var removeArgs struct {
	list bool
}

func removeProfile(ctx context.Context, args []string) error {
	if removeArgs.list {
		return listProfiles(ctx)
	}
	if len(args) != 1 {
		outln("usage: tailscale remove NAME")
		os.Exit(1)
	}
	cp, all, err := localClient.ProfileStatus(ctx)
	if err != nil {
		errf("Failed to remove account: %v\n", err)
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
	fmt.Println(profID)
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
	fmt.Println(profID)
	if profID == "" {
		errf("No profile named %q\n", args[0])
		os.Exit(1)
	}
	if profID == cp.ID {
		printf("Already on account %q\n", args[0])
		os.Exit(0)
	}

	err = localClient.DeleteProfile(ctx, profID)
	if err != nil {
		errf("Failed to remove account: %v\n", err)
		os.Exit(1)
	}

	printf("Removing account %q\n", args[0])
	for {
		select {
		case <-ctx.Done():
			errf("Timed out waiting for remove to complete.")
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
