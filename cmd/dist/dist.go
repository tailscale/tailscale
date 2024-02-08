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
	"tailscale.com/release/dist/synology"
	"tailscale.com/release/dist/unixpkgs"
)

var synologyPackageCenter bool

func getTargets() ([]dist.Target, error) {
	var ret []dist.Target

	ret = append(ret, unixpkgs.Targets(unixpkgs.Signers{})...)
	// Synology packages can be built either for sideloading, or for
	// distribution by Synology in their package center. When
	// distributed through the package center, apps can request
	// additional permissions to use a tuntap interface and control
	// the NAS's network stack, rather than be forced to run in
	// userspace mode.
	//
	// Since only we can provide packages to Synology for
	// distribution, we default to building the "sideload" variant of
	// packages that we distribute on pkgs.tailscale.com.
	//
	// To build for package center, run
	// ./tool/go run ./cmd/dist build --synology-package-center synology
	ret = append(ret, synology.Targets(synologyPackageCenter, nil)...)
	return ret, nil
}

func main() {
	cmd := cli.CLI(getTargets)
	for _, subcmd := range cmd.Subcommands {
		if subcmd.Name == "build" {
			subcmd.FlagSet.BoolVar(&synologyPackageCenter, "synology-package-center", false, "build synology packages with extra metadata for the official package center")
		}
	}

	if err := cmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
