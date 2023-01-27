// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_include_cli

package main

import (
	"fmt"
	"os"

	"tailscale.com/cmd/tailscale/cli"
)

func init() {
	beCLI = func() {
		args := os.Args[1:]
		if err := cli.Run(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
