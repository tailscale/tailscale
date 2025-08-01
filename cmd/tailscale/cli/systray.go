// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_systray

package cli

import (
	"context"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/systray"
)

var systrayCmd = &ffcli.Command{
	Name:       "systray",
	ShortUsage: "tailscale systray",
	ShortHelp:  "Run a systray application to manage Tailscale",
	Exec: func(_ context.Context, _ []string) error {
		// TODO(will): pass localClient to menu to use the global --socket flag
		new(systray.Menu).Run()
		return nil
	},
}
