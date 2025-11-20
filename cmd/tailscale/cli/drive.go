// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/drive"
)

const (
	driveShareUsage   = "tailscale drive share <name> <path>"
	driveRenameUsage  = "tailscale drive rename <oldname> <newname>"
	driveUnshareUsage = "tailscale drive unshare <name>"
	driveListUsage    = "tailscale drive list"
)

func init() {
	maybeDriveCmd = driveCmd
}

func driveCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:      "drive",
		ShortHelp: "Share a directory with your tailnet",
		ShortUsage: strings.Join([]string{
			driveShareUsage,
			driveRenameUsage,
			driveUnshareUsage,
			driveListUsage,
		}, "\n"),
		LongHelp:  buildShareLongHelp(),
		UsageFunc: usageFuncNoDefaultValues,
		Subcommands: []*ffcli.Command{
			{
				Name:       "share",
				ShortUsage: driveShareUsage,
				Exec:       runDriveShare,
				ShortHelp:  "[ALPHA] Create or modify a share",
			},
			{
				Name:       "rename",
				ShortUsage: driveRenameUsage,
				ShortHelp:  "[ALPHA] Rename a share",
				Exec:       runDriveRename,
			},
			{
				Name:       "unshare",
				ShortUsage: driveUnshareUsage,
				ShortHelp:  "[ALPHA] Remove a share",
				Exec:       runDriveUnshare,
			},
			{
				Name:       "list",
				ShortUsage: driveListUsage,
				ShortHelp:  "[ALPHA] List current shares",
				Exec:       runDriveList,
			},
		},
	}
}

// runDriveShare is the entry point for the "tailscale drive share" command.
func runDriveShare(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: %s", driveShareUsage)
	}

	name, path := args[0], args[1]

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	err = localClient.DriveShareSet(ctx, &drive.Share{
		Name: name,
		Path: absolutePath,
	})
	if err == nil {
		fmt.Printf("Sharing %q as %q\n", path, name)
	}
	return err
}

// runDriveUnshare is the entry point for the "tailscale drive unshare" command.
func runDriveUnshare(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s", driveUnshareUsage)
	}
	name := args[0]

	err := localClient.DriveShareRemove(ctx, name)
	if err == nil {
		fmt.Printf("No longer sharing %q\n", name)
	}
	return err
}

// runDriveRename is the entry point for the "tailscale drive rename" command.
func runDriveRename(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: %s", driveRenameUsage)
	}
	oldName := args[0]
	newName := args[1]

	err := localClient.DriveShareRename(ctx, oldName, newName)
	if err == nil {
		fmt.Printf("Renamed share %q to %q\n", oldName, newName)
	}
	return err
}

// runDriveList is the entry point for the "tailscale drive list" command.
func runDriveList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: %s", driveListUsage)
	}

	shares, err := localClient.DriveShareList(ctx)
	if err != nil {
		return err
	}

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
	if drive.AllowShareAs() {
		longHelpAs = shareLongHelpAs
	}
	return fmt.Sprintf(shareLongHelpBase, longHelpAs)
}

var shareLongHelpBase = `Taildrive allows you to share directories with other machines on your tailnet.

In order to share folders, your node needs to have the node attribute "drive:share".

In order to access shares, your node needs to have the node attribute "drive:access".

For example, to enable sharing and accessing shares for all member nodes:

  "nodeAttrs": [
    {
      "target": ["autogroup:member"],
      "attr": [
        "drive:share",
        "drive:access",
      ],
    }]

Each share is identified by a name and points to a directory at a specific path. For example, to share the path /Users/me/Documents under the name "docs", you would run:

  $ tailscale drive share docs /Users/me/Documents

Note that the system forces share names to lowercase to avoid problems with clients that don't support case-sensitive filenames.

Share names may only contain the letters a-z, underscore _, parentheses (), or spaces. Leading and trailing spaces are omitted.

All Tailscale shares have a globally unique path consisting of the tailnet, the machine name and the share name. For example, if the above share was created on the machine "mylaptop" on the tailnet "mydomain.com", the share's path would be:

  /mydomain.com/mylaptop/docs

In order to access this share, other machines on the tailnet can connect to the above path on a WebDAV server running at 100.100.100.100:8080, for example:

  http://100.100.100.100:8080/mydomain.com/mylaptop/docs

Permissions to access shares are controlled via ACLs. For example, to give the group "home" read-only access to the above share, use the below ACL grant:

  "grants": [
    {
      "src": ["group:home"],
      "dst": ["mylaptop"],
      "app": {
        "tailscale.com/cap/drive": [{
          "shares": ["docs"],
          "access": "ro"
        }]
      }
    }]

Whenever anyone in the group "home" connects to the share, they connect as if they are using your local machine user. They'll be able to read the same files as your user, and if they create files, those files will be owned by your user.%s

On small tailnets, it may be convenient to categorically give all users full access to their own shares. That can be accomplished with the below grant.

  "grants": [
	{
	  "src": ["autogroup:member"],
	  "dst": ["autogroup:self"],
	  "app": {
	    "tailscale.com/cap/drive": [{
		  "shares": ["*"],
		  "access": "rw"
	    }]
	  }
	}]

You can rename shares, for example you could rename the above share by running:

  $ tailscale drive rename docs newdocs

You can remove shares by name, for example you could remove the above share by running:

  $ tailscale drive unshare newdocs

You can get a list of currently published shares by running:

  $ tailscale drive list`

const shareLongHelpAs = `

If you want a share to be accessed as a different user, you can use sudo to accomplish this. For example, to create the aforementioned share as "theuser", you could run:

  $ sudo -u theuser tailscale drive share docs /Users/theuser/Documents`
