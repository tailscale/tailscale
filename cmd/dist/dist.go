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
	"tailscale.com/release/dist/qnap"
	"tailscale.com/release/dist/synology"
	"tailscale.com/release/dist/unixpkgs"
)

var (
	synologyPackageCenter bool
	qnapPrivateKeyPath    string
	qnapCertificatePath   string
)

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
	if (qnapPrivateKeyPath == "") != (qnapCertificatePath == "") {
		return nil, errors.New("both --qnap-private-key-path and --qnap-certificate-path must be set")
	}
	ret = append(ret, qnap.Targets(qnapPrivateKeyPath, qnapCertificatePath)...)
	return ret, nil
}

func main() {
	cmd := cli.CLI(getTargets)
	for _, subcmd := range cmd.Subcommands {
		if subcmd.Name == "build" {
			subcmd.FlagSet.BoolVar(&synologyPackageCenter, "synology-package-center", false, "build synology packages with extra metadata for the official package center")
			subcmd.FlagSet.StringVar(&qnapPrivateKeyPath, "qnap-private-key-path", "", "sign qnap packages with given key (must also provide --qnap-certificate-path)")
			subcmd.FlagSet.StringVar(&qnapCertificatePath, "qnap-certificate-path", "", "sign qnap packages with given certificate (must also provide --qnap-private-key-path)")
		}
	}

	if err := cmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}
