// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_systray

package cli

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/systray"
)

var systrayCmd = &ffcli.Command{
	Name:       "systray",
	ShortUsage: "tailscale systray",
	ShortHelp:  "Run a systray application to manage Tailscale",
	LongHelp:   "Run a systray application to manage Tailscale.",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("systray")
		fs.StringVar(&systrayArgs.theme, "theme", "dark", "color theme for Tailscale icon: dark, dark:nobg, light, light:nobg")
		return fs
	})(),
	Exec: runSystray,
}

var systrayArgs struct {
	theme string
}

func runSystray(ctx context.Context, _ []string) error {
	systray.SetTheme(systrayArgs.theme)
	new(systray.Menu).Run(&localClient)
	return nil
}
