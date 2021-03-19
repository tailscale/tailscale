// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/version"
)

var versionCmd = &ffcli.Command{
	Name:       "version",
	ShortUsage: "version [flags]",
	ShortHelp:  "Print Tailscale version",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("version", flag.ExitOnError)
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
		fmt.Println(version.String())
		return nil
	}

	fmt.Printf("Client: %s\n", version.String())

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	bc.AllowVersionSkew = true

	done := make(chan struct{})

	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if n.Engine != nil {
			fmt.Printf("Daemon: %s\n", n.Version)
			close(done)
		}
	})
	go pump(ctx, bc, c)

	bc.RequestEngineStatus()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
