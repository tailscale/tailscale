// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
)

var debugCmd = &ffcli.Command{
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.goroutines, "daemon-goroutines", false, "If true, dump the tailscaled daemon's goroutines")
		return fs
	})(),
}

var debugArgs struct {
	goroutines bool
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if debugArgs.goroutines {
		goroutines, err := tailscale.Goroutines(ctx)
		if err != nil {
			return err
		}
		os.Stdout.Write(goroutines)
	}
	return nil
}
