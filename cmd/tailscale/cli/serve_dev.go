// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

type execFunc func(ctx context.Context, args []string) error

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "Serve content and local servers on your tailnet",
		ShortUsage: strings.Join([]string{
			"serve <port>",
			"serve status [--json]",
		}, "\n  "),
		LongHelp: strings.TrimSpace(`
The 'tailscale serve' set of commands allows you to serve
content and local servers from your Tailscale node to
your tailnet.
`),
		Exec:      e.runServeDev(false),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve/Funnel status",
				FlagSet: e.newFlags("funnel-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runServeDev is the entry point for the "tailscale serve|funnel" subcommand.
//
// Note: funnel is only supported on single DNS name for now. (2023-08-18)
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
