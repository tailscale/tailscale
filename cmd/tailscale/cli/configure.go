// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/version/distro"
)

var configureCmd = &ffcli.Command{
	Name:      "configure",
	ShortHelp: "Configure the host to enable more Tailscale features",
	LongHelp: strings.TrimSpace(`
The 'configure' command is intended to provide a way to configure different
services on the host to enable more Tailscale features.
`),
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
