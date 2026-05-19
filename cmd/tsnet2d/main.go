// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet2d command is the out-of-process daemon backing the
// tailscale.com/tsnet2 package. One tsnet2d instance per tsnet2.Server
// (1:1) — see PLAN.tsnet2.md for the design.
//
// This binary is currently a skeleton: it parses its flags and exits
// with an error. The next implementation phase will fill in the
// daemon body (wgengine, LocalBackend, control channel, localapi
// channel, datapath channel, and the traffic logger).
package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	flagSocket     = flag.String("socket", "", "path to the Unix socket the daemon should listen on")
	flagStateDir   = flag.String("state-dir", "", "directory for daemon state (state store, logs, etc.)")
	flagTrafficLog = flag.String("traffic-log", "", "path to the JSON Lines traffic log file (defaults to <state-dir>/traffic.jsonl)")
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

	// The traffic log path is informational; the daemon will compute a
	// default if it is empty. Discarding it here just silences the
	// unused-variable warning.
	_ = *flagTrafficLog

	fmt.Fprintln(os.Stderr, "tsnet2d: not implemented")
	os.Exit(1)
}
