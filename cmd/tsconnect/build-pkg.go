// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/tailscale/hujson"
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

	if err := cleanDir(*pkgDir, "package.json"); err != nil {
		log.Fatalf("Cannot clean %s: %v", *pkgDir, err)
	}

	buildOptions.Write = true
	buildOptions.MinifyWhitespace = true
	buildOptions.MinifyIdentifiers = true
	buildOptions.MinifySyntax = true

	runEsbuild(*buildOptions)

	log.Printf("Generating types...\n")
	if err := runYarn("pkg-types"); err != nil {
		log.Fatalf("Type generation failed: %v", err)
	}

	if err := updateVersion(); err != nil {
		log.Fatalf("Cannot update version: %v", err)
	}

	log.Printf("Built package version %s", version.Long)
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
	if err := json.Unmarshal(packageJSONBytes, &packageJSON); err != nil {
		return fmt.Errorf("Could not unmarshal package.json: %w", err)
	}
	packageJSON["version"] = version.Long

	packageJSONBytes, err = json.MarshalIndent(packageJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("Could not marshal package.json: %w", err)
	}

	return os.WriteFile(path.Join(*pkgDir, "package.json"), packageJSONBytes, 0644)
}
