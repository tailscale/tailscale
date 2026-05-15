// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/util/clientmetric"
)

// metricBlueprintLeave counts `tailscale leave` invocations,
// regardless of outcome.
var metricBlueprintLeave = clientmetric.NewCounter("cli_blueprint_leave")

var leaveCmd = &ffcli.Command{
	Name:       "leave",
	ShortUsage: "tailscale leave",
	ShortHelp:  "Detach this node from its Blueprint and log out",
	LongHelp: `"tailscale leave" detaches a node that was brought up via
"tailscale join" from its bound Blueprint and logs the node out.
Blueprint-bound nodes are ephemeral; once detached, the node is
deleted from the tailnet server-side and any local registration
state is discarded. A subsequent "tailscale join" mints a fresh
node from scratch.

If the node is not blueprint-bound, "tailscale leave" still logs
the node out (same behavior as "tailscale logout") and emits a
note.`,
	FlagSet: newFlagSet("leave"),
	Exec: func(ctx context.Context, args []string) error {
		return runLeave(ctx, args)
	},
}

// runLeave logs out the current node. If the node is blueprint-bound,
// it first clears Prefs.BlueprintID so the lock-out on subsequent
// "tailscale set" calls is released even if the user reuses the
// state directory.
func runLeave(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected positional arguments: %q", args)
	}
	metricBlueprintLeave.Add(1)

	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("reading prefs: %w", err)
	}
	wasBound := curPrefs != nil && curPrefs.IsBlueprintBound()
	boundTo := ""
	if wasBound {
		boundTo = curPrefs.BlueprintID
		// Clear the binding marker first so a crash between
		// EditPrefs and Logout still leaves the node in a sensible
		// "not blueprint-bound" state.
		if _, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:          ipn.Prefs{BlueprintID: ""},
			BlueprintIDSet: true,
		}); err != nil {
			return fmt.Errorf("clearing blueprint binding: %w", err)
		}
	}

	if err := localClient.Logout(ctx); err != nil {
		return fmt.Errorf("logging out: %w", err)
	}
	metricBlueprintBound.Set(0)
	if wasBound {
		fmt.Printf("Detached from blueprint bp:%s and logged out.\n", boundTo)
	} else {
		fmt.Println("Logged out. (Node was not blueprint-bound.)")
	}
	return nil
}
