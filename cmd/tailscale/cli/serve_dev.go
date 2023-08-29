// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	ShortHelp string
	LongHelp  string
}

var infoMap = map[string]commandInfo{
	"serve": {
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Serve lets you  share a local server securely within your tailnet.",
			"To share a local server on the internet, use \"tailscale funnel\"",
		}, "\n"),
	},
	"funnel": {
		ShortHelp: "Serve content and local servers on the internet",
		LongHelp: strings.Join([]string{
			"Funnel lets you share a local server on the internet using Tailscale.",
			"To share only within your tailnet, use \"tailscale serve\"",
		}, "\n"),
	},
}

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv, subcmd string) *ffcli.Command {
	if subcmd != "serve" && subcmd != "funnel" {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]

	return &ffcli.Command{
		Name:      subcmd,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("%s <target>", subcmd),
			fmt.Sprintf("%s status [--json]", subcmd),
			fmt.Sprintf("%s reset", subcmd),
		}, "\n  "),
		LongHelp:  info.LongHelp,
		Exec:      e.runServeDev(subcmd == "funnel"),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			// TODO(tyler+marwan-at-work) Implement set, unset, and logs subcommands
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "view current proxy configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "reset",
				ShortHelp: "reset current serve/funnel config",
				Exec:      e.runServeReset,
				FlagSet:   e.newFlags("serve-reset", nil),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runServeDev is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeDev(funnel bool) execFunc {
	return func(ctx context.Context, args []string) error {
		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()
		if len(args) != 1 {
			return flag.ErrHelp
		}
		var source string
		port64, err := strconv.ParseUint(args[0], 10, 16)
		if err == nil {
			source = fmt.Sprintf("http://127.0.0.1:%d", port64)
		} else {
			source, err = expandProxyTarget(args[0])
		}
		if err != nil {
			return err
		}

		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}

		if funnel {
			if err := e.verifyFunnelEnabled(ctx, st, 443); err != nil {
				return err
			}
		}

		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
		hp := ipn.HostPort(dnsName + ":443") // TODO(marwan-at-work): support the 2 other ports

		// In the streaming case, the process stays running in the
		// foreground and prints out connections to the HostPort.
		//
		// The local backend handles updating the ServeConfig as
		// necessary, then restores it to its original state once
		// the process's context is closed or the client turns off
		// Tailscale.
		// TODO(tyler+marwan-at-work) support flag to run in the background
		return e.streamServe(ctx, ipn.ServeStreamRequest{
			Funnel:     funnel,
			HostPort:   hp,
			Source:     source,
			MountPoint: "/", // TODO(marwan-at-work): support multiple mount points
		})
	}
}

func (e *serveEnv) streamServe(ctx context.Context, req ipn.ServeStreamRequest) error {
	stream, err := e.lc.StreamServe(ctx, req)
	if err != nil {
		return err
	}
	defer stream.Close()

	fmt.Fprintf(os.Stderr, "Serve started on \"https://%s\".\n", strings.TrimSuffix(string(req.HostPort), ":443"))
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop.\n\n")
	_, err = io.Copy(os.Stdout, stream)
	return err
}
