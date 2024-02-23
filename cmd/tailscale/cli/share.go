// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tailfs"
)

const (
	shareAddUsage    = "share add <name> <path>"
	shareRemoveUsage = "share remove <name>"
	shareListUsage   = "share list"
)

var shareCmd = &ffcli.Command{
	Name:      "share",
	ShortHelp: "Share a directory with your tailnet",
	ShortUsage: strings.Join([]string{
		shareAddUsage,
		shareRemoveUsage,
		shareListUsage,
	}, "\n  "),
	LongHelp:  buildShareLongHelp(),
	UsageFunc: usageFuncNoDefaultValues,
	Subcommands: []*ffcli.Command{
		{
			Name:      "add",
			Exec:      runShareAdd,
			ShortHelp: "[ALPHA] add a share",
			UsageFunc: usageFunc,
		},
		{
			Name:      "remove",
			ShortHelp: "[ALPHA] remove a share",
			Exec:      runShareRemove,
			UsageFunc: usageFunc,
		},
		{
			Name:      "list",
			ShortHelp: "[ALPHA] list current shares",
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
		return fmt.Errorf("usage: tailscale %v", shareAddUsage)
	}

	name, path := args[0], args[1]

	err := localClient.TailFSShareAdd(ctx, &tailfs.Share{
		Name: name,
		Path: path,
	})
	if err == nil {
		fmt.Printf("Added share %q at %q\n", name, path)
	}
	return err
}

// runShareRemove is the entry point for the "tailscale share remove" command.
func runShareRemove(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: tailscale %v", shareRemoveUsage)
	}
	name := args[0]

	err := localClient.TailFSShareRemove(ctx, name)
	if err == nil {
		fmt.Printf("Removed share %q\n", name)
	}
	return err
}

// runShareList is the entry point for the "tailscale share list" command.
func runShareList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: tailscale %v", shareListUsage)
	}

	sharesMap, err := localClient.TailFSShareList(ctx)
	if err != nil {
		return err
	}
	shares := make([]*tailfs.Share, 0, len(sharesMap))
	for _, share := range sharesMap {
		shares = append(shares, share)
	}

	sort.Slice(shares, func(i, j int) bool {
		return shares[i].Name < shares[j].Name
	})

	longestName := 4 // "name"
	longestPath := 4 // "path"
	longestAs := 2   // "as"
	for _, share := range shares {
		if len(share.Name) > longestName {
			longestName = len(share.Name)
		}
		if len(share.Path) > longestPath {
			longestPath = len(share.Path)
		}
		if len(share.As) > longestAs {
			longestAs = len(share.As)
		}
	}
	formatString := fmt.Sprintf("%%-%ds    %%-%ds    %%s\n", longestName, longestPath)
	fmt.Printf(formatString, "name", "path", "as")
	fmt.Printf(formatString, strings.Repeat("-", longestName), strings.Repeat("-", longestPath), strings.Repeat("-", longestAs))
	for _, share := range shares {
		fmt.Printf(formatString, share.Name, share.Path, share.As)
	}

	return nil
}

func buildShareLongHelp() string {
	longHelpAs := ""
	if tailfs.AllowShareAs() {
		longHelpAs = shareLongHelpAs
	}
	return fmt.Sprintf(shareLongHelpBase, longHelpAs)
}

var shareLongHelpBase = `Tailscale share allows you to share directories with other machines on your tailnet.

In order to share folders, your node needs to have the node attribute "tailfs:share".

In order to access shares, your node needs to have the node attribute "tailfs:access".

For example, to enable sharing and accessing shares for all member nodes:

  "nodeAttrs": [
    {
      "target": ["autogroup:member"],
      "attr": [
        "tailfs:share",
        "tailfs:access",
      ],
    }]

Each share is identified by a name and points to a directory at a specific path. For example, to share the path /Users/me/Documents under the name "docs", you would run:

  $ tailscale share add docs /Users/me/Documents

Note that the system forces share names to lowercase to avoid problems with clients that don't support case-sensitive filenames.

Share names may only contain the letters a-z, underscore _, parentheses (), or spaces. Leading and trailing spaces are omitted.

All Tailscale shares have a globally unique path consisting of the tailnet, the machine name and the share name. For example, if the above share was created on the machine "mylaptop" on the tailnet "mydomain.com", the share's path would be:

  /mydomain.com/mylaptop/docs

In order to access this share, other machines on the tailnet can connect to the above path on a WebDAV server running at 100.100.100.100:8080, for example:

  http://100.100.100.100:8080/mydomain.com/mylaptop/docs

Permissions to access shares are controlled via ACLs. For example, to give yourself read/write access and give the group "home" read-only access to the above share, use the below ACL grants:

  "grants": [
    {
      "src": ["mylogin@domain.com"],
      "dst": ["mylaptop's ip address"],
      "app": {
        "tailscale.com/cap/tailfs": [{
          "shares": ["docs"],
          "access": "rw"
        }]
      }
    },
    {
      "src": ["group:home"],
      "dst": ["mylaptop"],
      "app": {
        "tailscale.com/cap/tailfs": [{
          "shares": ["docs"],
          "access": "ro"
        }]
      }
    }]

To categorically give yourself access to all your shares, you can use the below ACL grant:

  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "app": {
        "tailscale.com/cap/tailfs": [{
          "shares": ["*"],
          "access": "rw"
        }]
      }
    }]

Whenever either you or anyone in the group "home" connects to the share, they connect as if they are using your local machine user. They'll be able to read the same files as your user and if they create files, those files will be owned by your user.%s

You can remove shares by name, for example you could remove the above share by running:

  $ tailscale share remove docs

You can get a list of currently published shares by running:

  $ tailscale share list`

var shareLongHelpAs = `

If you want a share to be accessed as a different user, you can use sudo to accomplish this. For example, to create the aforementioned share as "theuser", you could run:

	$ sudo -u theuser tailscale share add docs /Users/theuser/Documents`
