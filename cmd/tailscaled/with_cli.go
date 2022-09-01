// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ts_include_cli
// +build ts_include_cli

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
