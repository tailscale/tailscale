// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
)

var downCmd = &ffcli.Command{
	Name:       "down",
	ShortUsage: "tailscale down",
	ShortHelp:  "Disconnect from Tailscale",

	Exec:    runDown,
	FlagSet: newDownFlagSet(),
}

var downArgs struct {
	acceptedRisks string
	reason        string
}

func newDownFlagSet() *flag.FlagSet {
	downf := newFlagSet("down")
	downf.StringVar(&downArgs.reason, "reason", "", "reason for the disconnect, if required by a policy")
	registerAcceptRiskFlag(downf, &downArgs.acceptedRisks)
	return downf
}

func runDown(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many non-flag arguments: %q", args)
	}

	if isSSHOverTailscale() {
		if err := presentRiskToUser(riskLoseSSH, `You are connected over Tailscale; this action will disable Tailscale and result in your session disconnecting.`, downArgs.acceptedRisks); err != nil {
			return err
		}
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("error fetching current status: %w", err)
	}
	if st.BackendState == "Stopped" {
		fmt.Fprintf(Stderr, "Tailscale was already stopped.\n")
		return nil
	}
	ctx = apitype.RequestReasonKey.WithValue(ctx, downArgs.reason)
	_, err = localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			WantRunning: false,
		},
		WantRunningSet: true,
	})
	return err
}
