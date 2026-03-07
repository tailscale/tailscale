// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_sync && !ts_mac_gui

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tailsync"
)

const (
	syncShareUsage   = "tailscale sync share <name> <path>"
	syncUnshareUsage = "tailscale sync unshare <name>"
	syncStartUsage   = "tailscale sync start <name> <local-root> <peer>:<remote-root> [--mode=two-way-safe|push|pull]"
	syncStopUsage    = "tailscale sync stop <session-name>"
	syncStatusUsage  = "tailscale sync status"
	syncListUsage    = "tailscale sync list"
)

func init() {
	maybeSyncCmd = syncCmd
}

func syncCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:      "sync",
		ShortHelp: "Sync directories with other machines on your tailnet",
		ShortUsage: strings.Join([]string{
			syncShareUsage,
			syncUnshareUsage,
			syncStartUsage,
			syncStopUsage,
			syncStatusUsage,
			syncListUsage,
		}, "\n"),
		LongHelp:  syncLongHelp,
		UsageFunc: usageFuncNoDefaultValues,
		Subcommands: []*ffcli.Command{
			{
				Name:       "share",
				ShortUsage: syncShareUsage,
				Exec:       runSyncShare,
				ShortHelp:  "Export a directory as a sync root",
			},
			{
				Name:       "unshare",
				ShortUsage: syncUnshareUsage,
				ShortHelp:  "Remove a sync root",
				Exec:       runSyncUnshare,
			},
			{
				Name:       "start",
				ShortUsage: syncStartUsage,
				ShortHelp:  "Start a sync session with a remote node",
				Exec:       runSyncStart,
			},
			{
				Name:       "stop",
				ShortUsage: syncStopUsage,
				ShortHelp:  "Stop a sync session",
				Exec:       runSyncStop,
			},
			{
				Name:       "status",
				ShortUsage: syncStatusUsage,
				ShortHelp:  "Show sync session statuses",
				Exec:       runSyncStatus,
			},
			{
				Name:       "list",
				ShortUsage: syncListUsage,
				ShortHelp:  "List sync roots and sessions",
				Exec:       runSyncList,
			},
		},
	}
}

// runSyncShare is the entry point for the "tailscale sync share" command.
func runSyncShare(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: %s", syncShareUsage)
	}

	name, path := args[0], args[1]

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	err = localClient.SyncRootSet(ctx, &tailsync.Root{
		Name: name,
		Path: absolutePath,
	})
	if err == nil {
		fmt.Printf("Sharing %q as sync root %q\n", path, name)
	}
	return err
}

// runSyncUnshare is the entry point for the "tailscale sync unshare" command.
func runSyncUnshare(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s", syncUnshareUsage)
	}

	err := localClient.SyncRootRemove(ctx, args[0])
	if err == nil {
		fmt.Printf("Removed sync root %q\n", args[0])
	}
	return err
}

// runSyncStart is the entry point for the "tailscale sync start" command.
func runSyncStart(ctx context.Context, args []string) error {
	if len(args) < 3 || len(args) > 4 {
		return fmt.Errorf("usage: %s", syncStartUsage)
	}

	name := args[0]
	localRoot := args[1]
	peerAndRoot := args[2]

	parts := strings.SplitN(peerAndRoot, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("remote must be in format <peer>:<root>")
	}

	mode := tailsync.ModeTwoWaySafe
	if len(args) == 4 {
		m := strings.TrimPrefix(args[3], "--mode=")
		mode = tailsync.Mode(m)
	}

	err := localClient.SyncSessionSet(ctx, &tailsync.Session{
		Name:       name,
		LocalRoot:  localRoot,
		PeerID:     parts[0],
		RemoteRoot: parts[1],
		Mode:       mode,
	})
	if err == nil {
		fmt.Printf("Started sync session %q: %s <-> %s:%s (mode=%s)\n", name, localRoot, parts[0], parts[1], mode)
	}
	return err
}

// runSyncStop is the entry point for the "tailscale sync stop" command.
func runSyncStop(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s", syncStopUsage)
	}

	err := localClient.SyncSessionRemove(ctx, args[0])
	if err == nil {
		fmt.Printf("Stopped sync session %q\n", args[0])
	}
	return err
}

// runSyncStatus is the entry point for the "tailscale sync status" command.
func runSyncStatus(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: %s", syncStatusUsage)
	}

	statuses, err := localClient.SyncStatus(ctx)
	if err != nil {
		return err
	}

	if len(statuses) == 0 {
		fmt.Println("No active sync sessions.")
		return nil
	}
	for _, st := range statuses {
		fmt.Printf("Session: %s\n", st.Name)
		fmt.Printf("  State:        %s\n", st.State)
		fmt.Printf("  Files synced: %d\n", st.FilesInSync)
		fmt.Printf("  Pending:      %d\n", st.FilesPending)
		if st.Error != "" {
			fmt.Printf("  Error:        %s\n", st.Error)
		}
		if len(st.Conflicts) > 0 {
			fmt.Printf("  Conflicts:    %d\n", len(st.Conflicts))
			for _, c := range st.Conflicts {
				fmt.Printf("    %s -> %s\n", c.Path, c.ConflictPath)
			}
		}
		if !st.LastSyncAt.IsZero() {
			fmt.Printf("  Last sync:    %s\n", st.LastSyncAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}
	return nil
}

// runSyncList is the entry point for the "tailscale sync list" command.
func runSyncList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: %s", syncListUsage)
	}

	roots, err := localClient.SyncRootList(ctx)
	if err != nil {
		return err
	}

	fmt.Println("Sync Roots:")
	if len(roots) == 0 {
		fmt.Println("  (none)")
	} else {
		longestName := 4 // "name"
		for _, r := range roots {
			if len(r.Name) > longestName {
				longestName = len(r.Name)
			}
		}
		formatString := fmt.Sprintf("  %%-%ds    %%s\n", longestName)
		fmt.Printf(formatString, "name", "path")
		fmt.Printf(formatString, strings.Repeat("-", longestName), strings.Repeat("-", 4))
		for _, r := range roots {
			fmt.Printf(formatString, r.Name, r.Path)
		}
	}

	sessions, err := localClient.SyncSessionList(ctx)
	if err != nil {
		return err
	}

	fmt.Println("\nSync Sessions:")
	if len(sessions) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, s := range sessions {
			fmt.Printf("  %s: %s <-> %s:%s (mode=%s)\n", s.Name, s.LocalRoot, s.PeerID, s.RemoteRoot, s.Mode)
		}
	}

	return nil
}

const syncLongHelp = `Tailsync provides bidirectional real-time file synchronization between nodes on your tailnet.

In order to export sync roots, your node needs the "sync:share" node attribute.
In order to sync with remote roots, your node needs the "sync:access" node attribute.

Example ACL configuration:

  "nodeAttrs": [
    {
      "target": ["autogroup:member"],
      "attr": [
        "sync:share",
        "sync:access",
      ],
    }]

To share a directory as a sync root:

  $ tailscale sync share myrepo /path/to/repo

To start syncing with a remote node:

  $ tailscale sync start mysession myrepo remote-server:myrepo

To check sync status:

  $ tailscale sync status

To stop syncing:

  $ tailscale sync stop mysession

To remove a sync root:

  $ tailscale sync unshare myrepo`
