// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The build-webclient tool generates the static resources needed for the
// web client (code at client/web).
//
// # Running
//
// Meant to be invoked from the tailscale/web-client-prebuilt repo when
// updating the production built web client assets. To run it manually,
// you can use `./tool/go run ./misc/build-webclient`
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"tailscale.com/util/precompress"
)

var (
	outDir = flag.String("outDir", "build/", "path to output directory")
)

func main() {
	flag.Parse()

	// The toolDir flag is relative to the current working directory,
	// so we need to resolve it to an absolute path.
	toolDir, err := filepath.Abs("./tool")
	if err != nil {
		log.Fatalf("Cannot resolve tool-dir: %v", err)
	}

	if err := build(toolDir, "client/web"); err != nil {
		log.Fatalf("%v", err)
	}
}

func build(toolDir, appDir string) error {
	if err := os.Chdir(appDir); err != nil {
		return fmt.Errorf("Cannot change cwd: %w", err)
	}

	if err := yarn(toolDir); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}

	if err := yarn(toolDir, "lint"); err != nil {
		return fmt.Errorf("lint failed: %w", err)
	}

	if err := yarn(toolDir, "build", "--outDir="+*outDir, "--emptyOutDir"); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	var compressedFiles []string
	if err := precompress.PrecompressDir(*outDir, precompress.Options{
		ProgressFn: func(path string) {
			log.Printf("Pre-compressing %v\n", path)
			compressedFiles = append(compressedFiles, path)
		},
	}); err != nil {
		return fmt.Errorf("Cannot precompress: %w", err)
	}

	// Cleanup pre-compressed files.
	for _, f := range compressedFiles {
		if err := os.Remove(f); err != nil {
			log.Printf("Failed to cleanup %q: %v", f, err)
		}
		// Removing intermediate ".br" version, we use ".gz" asset.
		if err := os.Remove(f + ".br"); err != nil {
			log.Printf("Failed to cleanup %q: %v", f+".gz", err)
		}
	}

	return nil
}

func yarn(toolDir string, args ...string) error {
	args = append([]string{"--silent", "--non-interactive"}, args...)
	return run(filepath.Join(toolDir, "yarn"), args...)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
