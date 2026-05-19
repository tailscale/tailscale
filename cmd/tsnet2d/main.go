// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet2d command is the out-of-process daemon backing the
// tailscale.com/tsnet2 package. One tsnet2d instance per tsnet2.Server
// (1:1) — see PLAN.tsnet2.md for the design.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/cmd/tsnet2d/daemon"
)

var (
	flagSocket     = flag.String("socket", "", "path to the Unix socket the daemon should listen on")
	flagStateDir   = flag.String("state-dir", "", "directory for daemon state (state store, logs, etc.)")
	flagTrafficLog = flag.String("traffic-log", "", "path to the JSON Lines traffic log file (defaults to <state-dir>/traffic.jsonl)")
	flagVerbose    = flag.Bool("v", false, "verbose daemon debug logging")
)

func main() {
	flag.Parse()

	if *flagSocket == "" {
		fmt.Fprintln(os.Stderr, "tsnet2d: --socket is required")
		os.Exit(2)
	}
	if *flagStateDir == "" {
		fmt.Fprintln(os.Stderr, "tsnet2d: --state-dir is required")
		os.Exit(2)
	}

	logf := log.Printf
	if !*flagVerbose {
		// Discard backend chatter unless -v was supplied; the daemon
		// still writes a single "pid=X listening on Y" line to stderr
		// on startup, which the integration test relies on.
		logf = func(string, ...any) {}
	}

	d, err := daemon.New(daemon.Config{
		SocketPath:     *flagSocket,
		StateDir:       *flagStateDir,
		TrafficLogPath: *flagTrafficLog,
		Logf:           logf,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tsnet2d: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Shut down gracefully on SIGINT/SIGTERM.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "tsnet2d: %v\n", err)
		d.Close()
		os.Exit(1)
	}
	d.Close()
}
