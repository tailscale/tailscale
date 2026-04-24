// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/drive"
)

const (
	driveShareUsage   = "tailscale drive share [--users user1,user2 | --group groupname] <name> <path>"
	driveRenameUsage  = "tailscale drive rename <oldname> <newname>"
	driveUnshareUsage = "tailscale drive unshare <name>"
	driveListUsage    = "tailscale drive list"
)

func init() {
	maybeDriveCmd = driveCmd
}

func driveCmd() *ffcli.Command {
	shareFlags := flag.NewFlagSet("share", flag.ContinueOnError)
	usersFlag := shareFlags.String("users", "", "comma-separated list of users to share with (share name auto-generated)")
	groupFlag := shareFlags.String("group", "", "group name to share with (share name auto-generated, only group members can access)")

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
				FlagSet:    shareFlags,
				Exec: func(ctx context.Context, args []string) error {
					return runDriveShare(ctx, args, *usersFlag, *groupFlag)
				},
				ShortHelp: "[ALPHA] Create or modify a share",
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
func runDriveShare(ctx context.Context, args []string, usersFlag, groupFlag string) error {
	if usersFlag != "" && groupFlag != "" {
		return fmt.Errorf("cannot specify both --users and --group")
	}

	var name, path string
	var isGroup bool

	switch {
	case usersFlag != "":
		// --users joe,rhea → name = "joe+rhea", path from args[0]
		if len(args) != 1 {
			return fmt.Errorf("usage: tailscale drive share --users user1,user2 <path>")
		}
		users := strings.Split(usersFlag, ",")
		for i, u := range users {
			users[i] = strings.TrimSpace(u)
			if users[i] == "" {
				return fmt.Errorf("empty username in --users flag")
			}
		}
		if err := validateUsers(ctx, users); err != nil {
			return err
		}
		sort.Strings(users)
		name = strings.Join(users, "+")
		path = args[0]

	case groupFlag != "":
		// --group eng → name = "eng", path from args[0]
		if len(args) != 1 {
			return fmt.Errorf("usage: tailscale drive share --group groupname <path>")
		}
		if err := validateGroup(ctx, groupFlag); err != nil {
			return err
		}
		name = groupFlag
		path = args[0]
		isGroup = true

	default:
		// Traditional: <name> <path>
		if len(args) != 2 {
			return fmt.Errorf("usage: %s", driveShareUsage)
		}
		name = args[0]
		path = args[1]
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	err = localClient.DriveShareSet(ctx, &drive.Share{
		Name:    name,
		Path:    absolutePath,
		IsGroup: isGroup,
	})
	if err == nil {
		fmt.Printf("Sharing %q as %q\n", path, name)
	}
	return err
}

// validateUsers checks that all specified usernames exist in the tailnet and
// resolves display names. It modifies users in place, replacing each entry
// with its resolved display name (which may include a domain qualifier for
// disambiguation). It returns an error if any user is unknown or ambiguous.
func validateUsers(ctx context.Context, users []string) error {
	status, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tailnet status: %w", err)
	}

	tailnetDomain := ""
	if status.CurrentTailnet != nil {
		tailnetDomain = status.CurrentTailnet.Name
	}

	// Build a map from short name to list of login names.
	type userInfo struct {
		loginName   string
		displayName string
	}
	shortToUsers := make(map[string][]userInfo)
	for _, u := range status.User {
		short := drive.LoginShortName(u.LoginName)
		display := drive.LoginDisplayName(u.LoginName, tailnetDomain)
		shortToUsers[short] = append(shortToUsers[short], userInfo{
			loginName:   u.LoginName,
			displayName: display,
		})
	}

	// Also build a lookup by display name for users specifying name(domain).
	displayToUser := make(map[string]userInfo)
	for _, infos := range shortToUsers {
		for _, info := range infos {
			displayToUser[info.displayName] = info
		}
	}

	for i, u := range users {
		// Check if user specified name(domain) form.
		if strings.Contains(u, "(") && strings.Contains(u, ")") {
			if _, ok := displayToUser[u]; !ok {
				known := make([]string, 0)
				for d := range displayToUser {
					known = append(known, d)
				}
				sort.Strings(known)
				return fmt.Errorf("unknown user %q\nvalid users: %s", u, strings.Join(known, ", "))
			}
			users[i] = u
			continue
		}

		// Plain short name lookup.
		matches, ok := shortToUsers[u]
		if !ok || len(matches) == 0 {
			known := make([]string, 0, len(shortToUsers))
			for k := range shortToUsers {
				known = append(known, k)
			}
			sort.Strings(known)
			return fmt.Errorf("unknown user %q\nvalid users: %s", u, strings.Join(known, ", "))
		}
		if len(matches) == 1 {
			users[i] = matches[0].displayName
			continue
		}
		// Ambiguous: multiple users share the same short name.
		options := make([]string, len(matches))
		for j, m := range matches {
			options[j] = m.displayName
		}
		sort.Strings(options)
		return fmt.Errorf("ambiguous user %q, did you mean: %s?", u, strings.Join(options, " or "))
	}
	return nil
}

// validateGroup checks that the specified group exists in the tailnet.
func validateGroup(ctx context.Context, group string) error {
	status, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tailnet status: %w", err)
	}

	knownGroups := make(map[string]bool)
	for _, u := range status.User {
		for _, g := range u.Groups {
			knownGroups[drive.GroupShortName(g)] = true
		}
	}

	if !knownGroups[group] {
		known := make([]string, 0, len(knownGroups))
		for k := range knownGroups {
			known = append(known, k)
		}
		sort.Strings(known)
		return fmt.Errorf("unknown group: %s\nvalid groups: %s", group, strings.Join(known, ", "))
	}
	return nil
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
