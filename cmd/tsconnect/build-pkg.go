// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	jsonv1 "encoding/json"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/tailscale/hujson"
	"tailscale.com/util/precompress"
	"tailscale.com/version"
)

func runBuildPkg() {
	buildOptions, err := commonPkgSetup(prodMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}

	log.Printf("Linting...\n")
	if err := runYarn("lint"); err != nil {
		log.Fatalf("Linting failed: %v", err)
	}

	if err := cleanDir(*pkgDir); err != nil {
		log.Fatalf("Cannot clean %s: %v", *pkgDir, err)
	}

	buildOptions.Write = true
	buildOptions.MinifyWhitespace = true
	buildOptions.MinifyIdentifiers = true
	buildOptions.MinifySyntax = true

	runEsbuild(*buildOptions)

	if err := precompressWasm(); err != nil {
		log.Fatalf("Could not pre-recompress wasm: %v", err)
	}

	log.Printf("Generating types...\n")
	if err := runYarn("pkg-types"); err != nil {
		log.Fatalf("Type generation failed: %v", err)
	}

	if err := updateVersion(); err != nil {
		log.Fatalf("Cannot update version: %v", err)
	}

	if err := copyReadme(); err != nil {
		log.Fatalf("Cannot copy readme: %v", err)
	}

	log.Printf("Built package version %s", version.Long())
}

func precompressWasm() error {
	log.Printf("Pre-compressing main.wasm...\n")
	return precompress.Precompress(path.Join(*pkgDir, "main.wasm"), precompress.Options{
		FastCompression: *fastCompression,
	})
}

func updateVersion() error {
	packageJSONBytes, err := os.ReadFile("package.json.tmpl")
	if err != nil {
		return fmt.Errorf("Could not read package.json: %w", err)
	}

	var packageJSON map[string]any
	packageJSONBytes, err = hujson.Standardize(packageJSONBytes)
	if err != nil {
		return fmt.Errorf("Could not standardize template package.json: %w", err)
	}
	if err := jsonv1.Unmarshal(packageJSONBytes, &packageJSON); err != nil {
		return fmt.Errorf("Could not unmarshal package.json: %w", err)
	}
	packageJSON["version"] = version.Long()

	packageJSONBytes, err = jsonv1.MarshalIndent(packageJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("Could not marshal package.json: %w", err)
	}

	return os.WriteFile(path.Join(*pkgDir, "package.json"), packageJSONBytes, 0644)
}

func copyReadme() error {
	readmeBytes, err := os.ReadFile("README.pkg.md")
	if err != nil {
		return fmt.Errorf("Could not read README.pkg.md: %w", err)
	}
	return os.WriteFile(path.Join(*pkgDir, "README.md"), readmeBytes, 0644)
}
