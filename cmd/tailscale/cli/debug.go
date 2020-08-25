// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/net/interfaces"
	"tailscale.com/wgengine/monitor"
)

var debugCmd = &ffcli.Command{
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.monitor, "monitor", false, "")
		return fs
	})(),
}

var debugArgs struct {
	monitor bool
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if debugArgs.monitor {
		return runMonitor(ctx)
	}
	return errors.New("only --monitor is available at the moment")
}

func runMonitor(ctx context.Context) error {
	dump := func() {
		st, err := interfaces.GetState()
		if err != nil {
			log.Printf("error getting state: %v", err)
			return
		}
		j, _ := json.MarshalIndent(st, "", "    ")
		os.Stderr.Write(j)
	}
	mon, err := monitor.New(log.Printf, func() {
		log.Printf("Link monitor fired. State:")
		dump()
	})
	if err != nil {
		return err
	}
	log.Printf("Starting link change monitor; initial state:")
	dump()
	mon.Start()
	log.Printf("Started link change monitor; waiting...")
	select {}
	return nil
}
