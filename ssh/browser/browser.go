// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Builds and serves the static site that is generated for the browser/Wasm
// Tailscale SSH client. Can be run in 3 modes:
// - dev: builds the site and serves it. JS and CSS changes can be picked up
//   with a reload.
// - build: builds the site and writes it to dist/
// - serve: serves the site from dist/ (embedded in the binary)
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

var (
	dev   = flag.Bool("dev", false, "Run in dev build and serve mode")
	build = flag.Bool("build", false, "Run in production build mode (generating static assets)")
	serve = flag.Bool("serve", false, "Run in production serve mode (serving static assets)")
	addr  = flag.String("addr", ":9090", "address to listen on")
)

func main() {
	flag.Parse()

	if *dev {
		runDev()
	} else if *build {
		runBuild()
	} else if *serve {
		runServe()
	} else {
		log.Fatal("No mode specified")
	}
}

func runDev() {
	buildOptions, err := commonSetup()
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}
	host, portStr, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("Cannot parse addr: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		log.Fatalf("Cannot parse port: %v", err)
	}
	result, err := esbuild.Serve(esbuild.ServeOptions{
		Port:     uint16(port),
		Host:     host,
		Servedir: "./",
	}, *buildOptions)
	if err != nil {
		log.Fatalf("Cannot start esbuild server: %v", err)
	}
	log.Printf("Listening on http://%s:%d\n", result.Host, result.Port)
	result.Wait()
}

func runBuild() {
	buildOptions, err := commonSetup()
	if err != nil {
		log.Fatalf("Cannot setup: %v", err)
	}

	if err := cleanDist(); err != nil {
		log.Fatalf("Cannot clean dist/: %v", err)
	}

	buildOptions.Write = true
	buildOptions.MinifyWhitespace = true
	buildOptions.MinifyIdentifiers = true
	buildOptions.MinifySyntax = true

	result := esbuild.Build(*buildOptions)
	if len(result.Errors) > 0 {
		log.Printf("ESBuild Error:\n")
		for _, e := range result.Errors {
			log.Printf("%v", e)
		}
		log.Fatal("Build failed")
	}
	if len(result.Warnings) > 0 {
		log.Printf("ESBuild Warnings:\n")
		for _, w := range result.Warnings {
			log.Printf("%v", w)
		}
	}
}

//go:embed dist/* index.html
var embeddedFS embed.FS

func runServe() {
	log.Printf("Listening on %s", *addr)
	err := http.ListenAndServe(*addr, http.FileServer(http.FS(embeddedFS)))
	if err != nil {
		log.Fatal(err)
	}
}

// commonSetup performs setup that is common to both dev and build modes.
func commonSetup() (*esbuild.BuildOptions, error) {
	// Change cwd to to where this file lives -- that's where all inputs for
	// esbuild and other build steps live.
	if _, filename, _, ok := runtime.Caller(0); ok {
		if err := os.Chdir(path.Dir(filename)); err != nil {
			return nil, fmt.Errorf("Cannot change cwd: %v", err)
		}
	}
	if err := buildDeps(); err != nil {
		return nil, fmt.Errorf("Cannot build deps: %v", err)
	}

	return &esbuild.BuildOptions{
		EntryPoints: []string{"src/index.js", "src/index.css"},
		Loader:      map[string]esbuild.Loader{".wasm": esbuild.LoaderFile},
		Outdir:      "./dist",
		Bundle:      true,
		Sourcemap:   esbuild.SourceMapLinked,
		LogLevel:    esbuild.LogLevelInfo,
		Define:      map[string]string{"DEBUG": strconv.FormatBool(*dev)},
		Target:      esbuild.ES2017,
	}, nil
}

// buildDeps builds the static assets that are needed for the server (except for
// JS/CSS bundling, which is  handled by esbuild).
func buildDeps() error {
	if err := copyWasmExec(); err != nil {
		return fmt.Errorf("Cannot copy wasm_exec.js: %v", err)
	}
	if err := buildWasm(); err != nil {
		return fmt.Errorf("Cannot build main.wasm: %v", err)
	}
	if err := installJsDeps(); err != nil {
		return fmt.Errorf("Cannot install JS deps: %v", err)
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
func buildWasm() error {
	log.Printf("Building wasm...\n")
	args := []string{"build", "-tags", "tailscale_go,osusergo,netgo,nethttpomithttp2,omitidna,omitpemdecrypt"}
	if !*dev {
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

// installJsDeps installs the JavaScript dependencies specified by package.json
func installJsDeps() error {
	log.Printf("Installing JS deps...\n")
	return exec.Command("yarn").Run()
}

// cleanDist removes files from the dist build directory, except the placeholder
// one that we keep to make sure Git still creates the directory.
func cleanDist() error {
	log.Printf("Cleaning dist/...\n")
	files, err := os.ReadDir("dist")
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.Name() != "placeholder" {
			if err := os.Remove(filepath.Join("dist", file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
