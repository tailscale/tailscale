// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"flag"
	"log"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/version"
)

var versionCmd = &ffcli.Command{
	Name:       "version",
	ShortUsage: "version [flags]",
	ShortHelp:  "Print Tailscale version",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("version")
		fs.BoolVar(&versionArgs.daemon, "daemon", false, "also print local node's daemon version")
		return fs
	})(),
	Exec: runVersion,
}

var versionArgs struct {
	daemon bool // also check local node's daemon version
}

func runVersion(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}
	if !versionArgs.daemon {
		outln(version.String())
		return nil
	}

	printf("Client: %s\n", version.String())

	st, err := tailscale.StatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	printf("Daemon: %s\n", st.Version)
	return nil
}
