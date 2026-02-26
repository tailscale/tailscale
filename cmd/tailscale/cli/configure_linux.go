// Copyright (c) Tailscale Inc & contributors
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

func init() {
	maybeSystrayCmd = systrayConfigCmd
}

var systrayArgs struct {
	initSystem     string
	installStartup bool
}

func systrayConfigCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "systray",
		ShortUsage: "tailscale configure systray [options]",
		ShortHelp:  "[ALPHA] Manage the systray client for Linux",
		LongHelp:   "[ALPHA] The systray set of commands provides a way to configure the systray application on Linux.",
		Exec:       configureSystray,
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("systray")
			fs.StringVar(&systrayArgs.initSystem, "enable-startup", "",
				"Install startup script for init system. Currently supported systems are [systemd, freedesktop].")
			return fs
		})(),
	}
}

func configureSystray(_ context.Context, _ []string) error {
	if systrayArgs.initSystem != "" {
		if err := systray.InstallStartupScript(systrayArgs.initSystem); err != nil {
			fmt.Printf("%s\n\n", err.Error())
			return flag.ErrHelp
		}
		return nil
	}
	return flag.ErrHelp
}
