// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package beaconcli implements the login beacon CLI without daemon dependencies.
package beaconcli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/feature/loginbeacon/api"
)

// Options supplies the host CLI's client, output, flags, and browser integration.
// NewFlagSet preserves the host's platform-specific error handling and output.
type Options struct {
	Client     *local.Client
	Stdout     io.Writer
	NewFlagSet func(string) *flag.FlagSet
	OpenURL    func(string) error
}

// NewCommand constructs the login-beacon command and its subcommands.
func NewCommand(opts Options) *ffcli.Command {
	lc := opts.Client
	var listJSON, statusJSON, printURL bool
	listFlags := opts.NewFlagSet("login-beacon-list")
	listFlags.BoolVar(&listJSON, "json", false, "output JSON")
	statusFlags := opts.NewFlagSet("login-beacon-status")
	statusFlags.BoolVar(&statusJSON, "json", false, "output JSON")
	approveFlags := opts.NewFlagSet("login-beacon-approve")
	approveFlags.BoolVar(&printURL, "print-url", false, "print the sensitive login URL instead of opening a local browser; retain the request for retry")
	return &ffcli.Command{
		Name: "login-beacon", ShortUsage: "tailscale login-beacon <list|watch|approve|delete|status|stop>",
		ShortHelp: "Manage LAN login requests [experimental]",
		Exec:      func(context.Context, []string) error { return flag.ErrHelp },
		Subcommands: []*ffcli.Command{
			{Name: "list", ShortUsage: "tailscale login-beacon list [--json]", ShortHelp: "List pending requests", FlagSet: listFlags, Exec: func(ctx context.Context, args []string) error {
				if len(args) != 0 {
					return flag.ErrHelp
				}
				requests, err := lc.LoginBeaconRequests(ctx)
				if err != nil {
					return err
				}
				if listJSON {
					return json.NewEncoder(opts.Stdout).Encode(requests)
				}
				for _, request := range requests {
					printBeaconRequest(opts.Stdout, request.Request)
				}
				return nil
			}},
			{Name: "status", ShortUsage: "tailscale login-beacon status [--json]", ShortHelp: "Show effective permission and activity", FlagSet: statusFlags, Exec: func(ctx context.Context, args []string) error {
				if len(args) != 0 {
					return flag.ErrHelp
				}
				status, err := lc.LoginBeaconStatus(ctx)
				if err != nil {
					return err
				}
				if statusJSON {
					return json.NewEncoder(opts.Stdout).Encode(status)
				}
				fmt.Fprintf(opts.Stdout, "Allowed by policy: %t\nReception enabled: %t\nReceiving: %t\nPending requests: %d\n", status.Allowed, status.AcceptRequests, status.Receiving, len(status.Requests))
				if status.BroadcastID != "" {
					fmt.Fprintf(opts.Stdout, "Broadcast: %s", status.BroadcastID)
					if !status.BroadcastExpires.IsZero() {
						fmt.Fprintf(opts.Stdout, " (expires %s)", status.BroadcastExpires.Format(time.RFC3339))
					}
					fmt.Fprintln(opts.Stdout)
				}
				return nil
			}},
			{Name: "watch", ShortUsage: "tailscale login-beacon watch", ShortHelp: "Show requests and their removal", Exec: func(ctx context.Context, args []string) error { return watchLoginBeacons(ctx, args, lc, opts.Stdout) }},
			{Name: "approve", ShortUsage: "tailscale login-beacon approve [--print-url] <request-id>", ShortHelp: "Open a request's login URL", FlagSet: approveFlags, Exec: func(ctx context.Context, args []string) error {
				if len(args) != 1 {
					return flag.ErrHelp
				}
				result, err := lc.ApproveLoginBeacon(ctx, args[0])
				if err != nil {
					return err
				}
				if !api.DefaultURLAllowed(result.AuthURL) {
					return fmt.Errorf("login beacon returned an untrusted authentication origin")
				}
				// Policy, deletion or profile changes may win while retrieval completes.
				status, err := lc.LoginBeaconStatus(ctx)
				if err != nil {
					return err
				}
				pending := false
				for _, request := range status.Requests {
					if request.RequestID == result.RequestID {
						pending = true
						break
					}
				}
				if !status.Allowed || !status.AcceptRequests || !pending || ctx.Err() != nil {
					return fmt.Errorf("login request is no longer available")
				}
				if printURL {
					fmt.Fprintln(opts.Stdout, result.AuthURL)
					return nil
				}
				open := opts.OpenURL
				if open == nil {
					return fmt.Errorf("browser opening unavailable; use --print-url")
				}
				// Browser errors can contain the sensitive URL. Keep it out of diagnostics.
				if err := open(result.AuthURL); err != nil {
					return fmt.Errorf("unable to open browser; retry or use --print-url")
				}
				return lc.DeleteLoginBeacon(ctx, result.RequestID)
			}},
			{Name: "delete", ShortUsage: "tailscale login-beacon delete <request-id>", ShortHelp: "Delete and suppress a request", Exec: func(ctx context.Context, args []string) error {
				if len(args) != 1 {
					return flag.ErrHelp
				}
				return lc.DeleteLoginBeacon(ctx, args[0])
			}},
			{Name: "stop", ShortUsage: "tailscale login-beacon stop", ShortHelp: "Stop the current broadcast attempt", Exec: func(ctx context.Context, args []string) error {
				if len(args) != 0 {
					return flag.ErrHelp
				}
				status, err := lc.LoginBeaconStatus(ctx)
				if err != nil {
					return err
				}
				if status.BroadcastID == "" {
					return nil
				}
				return lc.StopLoginBeacon(ctx, status.BroadcastID)
			}},
		},
	}
}

func watchLoginBeacons(ctx context.Context, args []string, lc *local.Client, out io.Writer) error {
	if len(args) != 0 {
		return flag.ErrHelp
	}
	// Subscribe first: reconcile the snapshot and queued announcements by ID.
	watcher, err := lc.WatchIPNBus(ctx, 0)
	if err != nil {
		return err
	}
	defer watcher.Close()
	requests, err := lc.LoginBeaconRequests(ctx)
	if err != nil {
		return err
	}
	// Removal notifications keep this set in step with the bounded daemon cache.
	seen := map[string]bool{}
	show := func(request api.Request) {
		if _, ok := seen[request.RequestID]; ok {
			return
		}
		if len(seen) >= api.MaxTrackedRequests {
			return
		}
		seen[request.RequestID] = true
		printBeaconRequest(out, request)
	}
	for _, request := range requests {
		show(request.Request)
	}
	for {
		n, err := watcher.Next()
		if err != nil {
			return err
		}
		if n.ErrMessage != nil {
			return fmt.Errorf("beacon notification stream closed; restart watch to refresh requests")
		}
		if n.LoginBeaconRequest != nil {
			show(*n.LoginBeaconRequest)
		}
		if n.LoginBeaconRemoved != nil {
			id := *n.LoginBeaconRemoved
			if _, ok := seen[id]; ok {
				fmt.Fprintf(out, "%s  request removed\n", id)
				delete(seen, id)
			}
		}
	}
}

func printBeaconRequest(out io.Writer, request api.Request) {
	fmt.Fprintf(out, "%s  %s wants to join Tailscale\n", request.RequestID, beaconLabel(request.Hostname))
}

func beaconLabel(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "Unknown device"
	}
	return name
}
