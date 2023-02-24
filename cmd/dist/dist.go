// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The dist command builds Tailscale release packages for distribution.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"

	"tailscale.com/release/dist"
	"tailscale.com/release/dist/cli"
	"tailscale.com/release/dist/unixpkgs"
)

func getTargets() ([]dist.Target, error) {
	return unixpkgs.Targets(), nil
}

func main() {
	cmd := cli.CLI(getTargets)
	if err := cmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
