// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
)

var debugCmd = &ffcli.Command{
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.goroutines, "daemon-goroutines", false, "If true, dump the tailscaled daemon's goroutines")
		fs.BoolVar(&debugArgs.ipn, "ipn", false, "If true, subscribe to IPN notifications")
		fs.BoolVar(&debugArgs.netMap, "netmap", true, "whether to include netmap in --ipn mode")
		return fs
	})(),
}

var debugArgs struct {
	goroutines bool
	ipn        bool
	netMap     bool
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
		return nil
	}
	if debugArgs.ipn {
		c, bc, ctx, cancel := connect(ctx)
		defer cancel()

		bc.SetNotifyCallback(func(n ipn.Notify) {
			if !debugArgs.netMap {
				n.NetMap = nil
			}
			j, _ := json.MarshalIndent(n, "", "\t")
			fmt.Printf("%s\n", j)
		})
		bc.RequestEngineStatus()
		pump(ctx, bc, c)
		return errors.New("exit")
	}
	return nil
}
