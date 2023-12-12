// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tailfs"
)

var shareHelpCommon = strings.TrimSpace(`
<name> is the name under which it will be shared

<directory> is the directory to share

EXAMPLES
  - Share $HOME/Downloads as "downloads"
    $ tailscale %[1]s downloads $HOME/Downloads

For more examples and use cases visit our docs site ...
`)

const (
	shareAddUsage    = "share add [-as <username] <name> <path>"
	shareRemoveUsage = "share remove <name>"
	shareListUsage   = "share list"
)

var shareAddArgs struct {
	as string
}

// newShareCommand returns a new "share" subcommand using e as its environment.
var shareCmd = &ffcli.Command{
	Name:      "share",
	ShortHelp: "Share a directory with your tailnet",
	ShortUsage: strings.Join([]string{
		shareAddUsage,
		shareRemoveUsage,
		shareListUsage,
	}, "\n  "),
	LongHelp:  "Not sure what to put here ...", // TODO(oxtoacart) add long help
	UsageFunc: usageFuncNoDefaultValues,
	Subcommands: []*ffcli.Command{
		{
			Name:      "add",
			Exec:      runShareAdd,
			ShortHelp: "add a share",
			UsageFunc: usageFunc,
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("add")
				fs.StringVar(&shareAddArgs.as, "as", "", "shares files as this user, must be root or a local admin to use this flag")
				return fs
			})(),
		},
		{
			Name:      "remove",
			ShortHelp: "remove a share",
			Exec:      runShareRemove,
			UsageFunc: usageFunc,
		},
		{
			Name:      "list",
			ShortHelp: "list current shares",
			Exec:      runShareList,
			UsageFunc: usageFunc,
		},
	},
	Exec: func(context.Context, []string) error {
		return errors.New("share subcommand required; run 'tailscale share -h' for details")
	},
}

// runShareAdd is the entry point for the "tailscale share add" command.
func runShareAdd(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: tailscale %v:", shareAddUsage)
	}

	return localClient.ShareAdd(ctx, &tailfs.Share{
		Name: args[0],
		Path: args[1],
		As:   shareAddArgs.as,
	})
}

// runShareRemove is the entry point for the "tailscale share remove" command.
func runShareRemove(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: tailscale %v:", shareRemoveUsage)
	}

	return localClient.ShareRemove(ctx, args[0])
}

// runShareList is the entry point for the "tailscale share list" command.
func runShareList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: tailscale %v:", shareListUsage)
	}

	sharesMap, err := localClient.ShareList(ctx)
	if err != nil {
		return err
	}
	shares := make([]*tailfs.Share, 0, len(sharesMap))
	for _, share := range sharesMap {
		shares = append(shares, share)
	}

	sort.Slice(shares, func(i, j int) bool {
		return strings.ToLower(shares[i].Name) < strings.ToLower(shares[j].Name)
	})

	longestName := 4 // "name"
	longestPath := 4 // "path"
	for _, share := range shares {
		if len(share.Name) > longestName {
			longestName = len(share.Name)
		}
		if len(share.Path) > longestPath {
			longestPath = len(share.Path)
		}
	}
	formatString := fmt.Sprintf("%%-%ds    %%s\n", longestName)
	fmt.Printf(formatString, "name", "path")
	fmt.Printf(formatString, strings.Repeat("-", longestName), strings.Repeat("-", longestPath))
	for _, share := range shares {
		fmt.Printf(formatString, share.Name, share.Path)
	}

	return nil
}
