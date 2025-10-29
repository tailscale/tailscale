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
	"path/filepath"

	"tailscale.com/util/precompress"
)

func runBuild() {
	buildOptions, err := commonSetup(prodMode)
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}

	log.Printf("Linting...\n")
	if err := runYarn("lint"); err != nil {
		log.Fatalf("Linting failed: %v", err)
	}

	if err := cleanDir(*distDir, "placeholder"); err != nil {
		log.Fatalf("Cannot clean %s: %v", *distDir, err)
	}

	buildOptions.Write = true
	buildOptions.MinifyWhitespace = true
	buildOptions.MinifyIdentifiers = true
	buildOptions.MinifySyntax = true

	buildOptions.EntryNames = "[dir]/[name]-[hash]"
	buildOptions.AssetNames = "[name]-[hash]"
	buildOptions.Metafile = true

	result := runEsbuild(*buildOptions)

	// Preserve build metadata so we can extract hashed file names for serving.
	metadataBytes, err := fixEsbuildMetadataPaths(result.Metafile)
	if err != nil {
		log.Fatalf("Cannot fix esbuild metadata paths: %v", err)
	}
	if err := os.WriteFile(path.Join(*distDir, "/esbuild-metadata.json"), metadataBytes, 0666); err != nil {
		log.Fatalf("Cannot write metadata: %v", err)
	}

	if er := precompressDist(*fastCompression); err != nil {
		log.Fatalf("Cannot precompress resources: %v", er)
	}
}

// fixEsbuildMetadataPaths re-keys the esbuild metadata file to use paths
// relative to the dist directory (it normally uses paths relative to the cwd,
// which are awkward if we're running with a different cwd at serving time).
func fixEsbuildMetadataPaths(metadataStr string) ([]byte, error) {
	var metadata EsbuildMetadata
	if err := jsonv1.Unmarshal([]byte(metadataStr), &metadata); err != nil {
		return nil, fmt.Errorf("Cannot parse metadata: %w", err)
	}
	distAbsPath, err := filepath.Abs(*distDir)
	if err != nil {
		return nil, fmt.Errorf("Cannot get absolute path from %s: %w", *distDir, err)
	}
	for outputPath, output := range metadata.Outputs {
		outputAbsPath, err := filepath.Abs(outputPath)
		if err != nil {
			return nil, fmt.Errorf("Cannot get absolute path from %s: %w", outputPath, err)
		}
		outputRelPath, err := filepath.Rel(distAbsPath, outputAbsPath)
		if err != nil {
			return nil, fmt.Errorf("Cannot get relative path from %s: %w", outputRelPath, err)
		}
		delete(metadata.Outputs, outputPath)
		metadata.Outputs[outputRelPath] = output
	}
	return jsonv1.Marshal(metadata)
}

func precompressDist(fastCompression bool) error {
	log.Printf("Pre-compressing files in %s/...\n", *distDir)
	return precompress.PrecompressDir(*distDir, precompress.Options{
		FastCompression: fastCompression,
		ProgressFn: func(path string) {
			log.Printf("Pre-compressing %v\n", path)
		},
	})
}
