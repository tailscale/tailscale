// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

const (
	devMode  = true
	prodMode = false
)

// commonSetup performs setup that is common to both dev and build modes.
func commonSetup(dev bool) (*esbuild.BuildOptions, error) {
	// Change cwd to to where this file lives -- that's where all inputs for
	// esbuild and other build steps live.
	if _, filename, _, ok := runtime.Caller(0); ok {
		if err := os.Chdir(path.Dir(filename)); err != nil {
			return nil, fmt.Errorf("Cannot change cwd: %w", err)
		}
	}
	if err := buildDeps(dev); err != nil {
		return nil, fmt.Errorf("Cannot build deps: %w", err)
	}

	return &esbuild.BuildOptions{
		EntryPoints: []string{"src/index.ts", "src/index.css"},
		Loader:      map[string]esbuild.Loader{".wasm": esbuild.LoaderFile},
		Outdir:      *distDir,
		Bundle:      true,
		Sourcemap:   esbuild.SourceMapLinked,
		LogLevel:    esbuild.LogLevelInfo,
		Define:      map[string]string{"DEBUG": strconv.FormatBool(dev)},
		Target:      esbuild.ES2017,
		Plugins: []esbuild.Plugin{{
			Name: "tailscale-tailwind",
			Setup: func(build esbuild.PluginBuild) {
				setupEsbuildTailwind(build, dev)
			},
		}},
	}, nil
}

// buildDeps builds the static assets that are needed for the server (except for
// JS/CSS bundling, which is  handled by esbuild).
func buildDeps(dev bool) error {
	if err := copyWasmExec(); err != nil {
		return fmt.Errorf("Cannot copy wasm_exec.js: %w", err)
	}
	if err := buildWasm(dev); err != nil {
		return fmt.Errorf("Cannot build main.wasm: %w", err)
	}
	if err := installJSDeps(); err != nil {
		return fmt.Errorf("Cannot install JS deps: %w", err)
	}
	return nil
}

// copyWasmExec grabs the current wasm_exec.js runtime helper library from the
// Go toolchain.
func copyWasmExec() error {
	log.Printf("Copying wasm_exec.js...\n")
	wasmExecSrcPath := filepath.Join(runtime.GOROOT(), "misc", "wasm", "wasm_exec.js")
	wasmExecDstPath := filepath.Join("src", "wasm_exec.js")
	contents, err := os.ReadFile(wasmExecSrcPath)
	if err != nil {
		return err
	}
	return os.WriteFile(wasmExecDstPath, contents, 0600)
}

// buildWasm builds the Tailscale wasm binary and places it where the JS can
// load it.
func buildWasm(dev bool) error {
	log.Printf("Building wasm...\n")
	args := []string{"build", "-tags", "tailscale_go,osusergo,netgo,nethttpomithttp2,omitidna,omitpemdecrypt"}
	if !dev {
		// Omit long paths and debug symbols in release builds, to reduce the
		// generated WASM binary size.
		args = append(args, "-trimpath", "-ldflags", "-s -w")
	}
	args = append(args, "-o", "src/main.wasm", "./wasm")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// installJSDeps installs the JavaScript dependencies specified by package.json
func installJSDeps() error {
	log.Printf("Installing JS deps...\n")
	return runYarn()
}

func runYarn(args ...string) error {
	cmd := exec.Command(*yarnPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// EsbuildMetadata is the subset of metadata struct (described by
// https://esbuild.github.io/api/#metafile) that we care about for mapping
// from entry points to hashed file names.
type EsbuildMetadata struct {
	Outputs map[string]struct {
		EntryPoint string `json:"entryPoint,omitempty"`
	} `json:"outputs,omitempty"`
}

func setupEsbuildTailwind(build esbuild.PluginBuild, dev bool) {
	build.OnLoad(esbuild.OnLoadOptions{
		Filter: "./src/index.css$",
	}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
		start := time.Now()
		yarnArgs := []string{"--silent", "tailwind", "-i", args.Path}
		if !dev {
			yarnArgs = append(yarnArgs, "--minify")
		}
		cmd := exec.Command(*yarnPath, yarnArgs...)
		tailwindOutput, err := cmd.Output()
		log.Printf("Ran tailwind in %v\n", time.Since(start))
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				log.Printf("Tailwind stderr: %s", exitErr.Stderr)
			}
			return esbuild.OnLoadResult{}, fmt.Errorf("Cannot run tailwind: %w", err)
		}
		tailwindOutputStr := string(tailwindOutput)
		return esbuild.OnLoadResult{
			Contents: &tailwindOutputStr,
			Loader:   esbuild.LoaderCSS,
		}, nil

	})
}
