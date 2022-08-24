// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

func runBuildPkg() {
	buildOptions, err := commonSetup(prodMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}

	log.Printf("Linting...\n")
	if err := runYarn("lint"); err != nil {
		log.Fatalf("Linting failed: %v", err)
	}

	if err := cleanDir(*pkgDir, "package.json"); err != nil {
		log.Fatalf("Cannot clean %s: %v", *pkgDir, err)
	}

	buildOptions.EntryPoints = []string{"src/pkg/pkg.ts", "src/pkg/pkg.css"}
	buildOptions.Outdir = *pkgDir
	buildOptions.Format = esbuild.FormatESModule
	buildOptions.AssetNames = "[name]"
	buildOptions.Write = true
	buildOptions.MinifyWhitespace = true
	buildOptions.MinifyIdentifiers = true
	buildOptions.MinifySyntax = true

	runEsbuild(*buildOptions)

	log.Printf("Generating types...\n")
	if err := runYarn("pkg-types"); err != nil {
		log.Fatalf("Type generation failed: %v", err)
	}

}
