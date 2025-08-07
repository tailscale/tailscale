// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_systray

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/systray"
)

var systrayArgs struct {
	initSystem     string
	installStartup bool
}

var systrayCmd = &ffcli.Command{
	Name:       "systray",
	ShortUsage: "tailscale systray",
	ShortHelp:  "Run a systray application to manage Tailscale",
	LongHelp: `Run a systray application to manage Tailscale.
To have the application run on startup, use the --enable-startup flag.`,
	Exec: runSystray,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("systray")
		fs.StringVar(&systrayArgs.initSystem, "enable-startup", "",
			"Install startup script for init system. Currently supported systems are [systemd].")
		return fs
	})(),
}

func runSystray(ctx context.Context, _ []string) error {
	if systrayArgs.initSystem != "" {
		if err := systray.InstallStartupScript(systrayArgs.initSystem); err != nil {
			fmt.Printf("%s\n\n", err.Error())
			return flag.ErrHelp
		}
		return nil
	}
	new(systray.Menu).Run(&localClient)
	return nil
}
