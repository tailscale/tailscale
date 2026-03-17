// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && ts_mac_gui

package cli

import (
	"context"
	"errors"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func init() {
	maybeDriveCmd = driveCmdStub
}

func driveCmdStub() *ffcli.Command {
	return &ffcli.Command{
		Name:       "drive",
		ShortHelp:  "Share a directory with your tailnet",
		ShortUsage: "tailscale drive [...any]",
		LongHelp:   hidden + "Taildrive allows you to share directories with other machines on your tailnet.",
		Exec: func(_ context.Context, args []string) error {
			return errors.New(
				"Taildrive CLI commands are not supported when using the macOS GUI app. " +
					"Please use the Tailscale menu bar icon to configure Taildrive in Settings.\n\n" +
					"See https://tailscale.com/docs/features/taildrive",
			)
		},
	}
}
