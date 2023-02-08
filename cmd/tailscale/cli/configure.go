// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"runtime"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/version/distro"
)

var configureCmd = &ffcli.Command{
	Name: "configure",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("configure")
		return fs
	})(),
	Subcommands: configureSubcommands(),
	Exec: func(ctx context.Context, args []string) error {
		return flag.ErrHelp
	},
}

func configureSubcommands() (out []*ffcli.Command) {
	if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
		out = append(out, synologyConfigureCmd)
	}
	return out
}
