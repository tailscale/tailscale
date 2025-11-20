// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_debugportmapper

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
)

func init() {
	debugPortmapCmd = mkDebugPortmapCmd
}

func mkDebugPortmapCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "portmap",
		ShortUsage: "tailscale debug portmap",
		Exec:       debugPortmap,
		ShortHelp:  "Run portmap debugging",
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("portmap")
			fs.DurationVar(&debugPortmapArgs.duration, "duration", 5*time.Second, "timeout for port mapping")
			fs.StringVar(&debugPortmapArgs.ty, "type", "", `portmap debug type (one of "", "pmp", "pcp", or "upnp")`)
			fs.StringVar(&debugPortmapArgs.gatewayAddr, "gateway-addr", "", `override gateway IP (must also pass --self-addr)`)
			fs.StringVar(&debugPortmapArgs.selfAddr, "self-addr", "", `override self IP (must also pass --gateway-addr)`)
			fs.BoolVar(&debugPortmapArgs.logHTTP, "log-http", false, `print all HTTP requests and responses to the log`)
			return fs
		})(),
	}
}

var debugPortmapArgs struct {
	duration    time.Duration
	gatewayAddr string
	selfAddr    string
	ty          string
	logHTTP     bool
}

func debugPortmap(ctx context.Context, args []string) error {
	opts := &local.DebugPortmapOpts{
		Duration: debugPortmapArgs.duration,
		Type:     debugPortmapArgs.ty,
		LogHTTP:  debugPortmapArgs.logHTTP,
	}
	if (debugPortmapArgs.gatewayAddr != "") != (debugPortmapArgs.selfAddr != "") {
		return fmt.Errorf("if one of --gateway-addr and --self-addr is provided, the other must be as well")
	}
	if debugPortmapArgs.gatewayAddr != "" {
		var err error
		opts.GatewayAddr, err = netip.ParseAddr(debugPortmapArgs.gatewayAddr)
		if err != nil {
			return fmt.Errorf("invalid --gateway-addr: %w", err)
		}
		opts.SelfAddr, err = netip.ParseAddr(debugPortmapArgs.selfAddr)
		if err != nil {
			return fmt.Errorf("invalid --self-addr: %w", err)
		}
	}
	rc, err := localClient.DebugPortmap(ctx, opts)
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = io.Copy(os.Stdout, rc)
	return err
}
