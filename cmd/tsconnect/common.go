// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
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
	root, err := findRepoRoot()
	if err != nil {
		return nil, err
	}
	if *yarnPath == "" {
		*yarnPath = path.Join(root, "tool", "yarn")
	}
	tsConnectDir := filepath.Join(root, "cmd", "tsconnect")
	if err := os.Chdir(tsConnectDir); err != nil {
		return nil, fmt.Errorf("Cannot change cwd: %w", err)
	}
	if err := installJSDeps(); err != nil {
		return nil, fmt.Errorf("Cannot install JS deps: %w", err)
	}

	return &esbuild.BuildOptions{
		EntryPoints: []string{"src/app/index.ts", "src/app/index.css"},
		Outdir:      *distDir,
		Bundle:      true,
		Sourcemap:   esbuild.SourceMapLinked,
		LogLevel:    esbuild.LogLevelInfo,
		Define:      map[string]string{"DEBUG": strconv.FormatBool(dev)},
		Target:      esbuild.ES2017,
		Plugins: []esbuild.Plugin{
			{
				Name: "tailscale-tailwind",
				Setup: func(build esbuild.PluginBuild) {
					setupEsbuildTailwind(build, dev)
				},
			},
			{
				Name:  "tailscale-go-wasm-exec-js",
				Setup: setupEsbuildWasmExecJS,
			},
			{
				Name: "tailscale-wasm",
				Setup: func(build esbuild.PluginBuild) {
					setupEsbuildWasm(build, dev)
				},
			},
		},
		JSX: esbuild.JSXAutomatic,
	}, nil
}

func findRepoRoot() (string, error) {
	if *rootDir != "" {
		return *rootDir, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(path.Join(cwd, "go.mod")); err == nil {
			return cwd, nil
		}
		if cwd == "/" {
			return "", fmt.Errorf("Cannot find repo root")
		}
		cwd = path.Dir(cwd)
	}
}

func commonPkgSetup(dev bool) (*esbuild.BuildOptions, error) {
	buildOptions, err := commonSetup(dev)
	if err != nil {
		return nil, err
	}
	buildOptions.EntryPoints = []string{"src/pkg/pkg.ts", "src/pkg/pkg.css"}
	buildOptions.Outdir = *pkgDir
	buildOptions.Format = esbuild.FormatESModule
	buildOptions.AssetNames = "[name]"
	return buildOptions, nil
}

// cleanDir removes files from dirPath, except the ones specified by
// preserveFiles.
func cleanDir(dirPath string, preserveFiles ...string) error {
	log.Printf("Cleaning %s...\n", dirPath)
	files, err := os.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dirPath, 0755)
		}
		return err
	}

	for _, file := range files {
		if !slices.Contains(preserveFiles, file.Name()) {
			if err := os.Remove(filepath.Join(dirPath, file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func runEsbuildServe(buildOptions esbuild.BuildOptions) {
	host, portStr, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("Cannot parse addr: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		log.Fatalf("Cannot parse port: %v", err)
	}
	buildContext, ctxErr := esbuild.Context(buildOptions)
	if ctxErr != nil {
		log.Fatalf("Cannot create esbuild context: %v", err)
	}
	result, err := buildContext.Serve(esbuild.ServeOptions{
		Port:     uint16(port),
		Host:     host,
		Servedir: "./",
	})
	if err != nil {
		log.Fatalf("Cannot start esbuild server: %v", err)
	}
	log.Printf("Listening on http://%s:%d\n", result.Host, result.Port)
	select {}
}

func runEsbuild(buildOptions esbuild.BuildOptions) esbuild.BuildResult {
	log.Printf("Running esbuild...\n")
	result := esbuild.Build(buildOptions)
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
	return result
}

// setupEsbuildWasmExecJS generates an esbuild plugin that serves the current
// wasm_exec.js runtime helper library from the Go toolchain.
func setupEsbuildWasmExecJS(build esbuild.PluginBuild) {
	wasmExecSrcPath := filepath.Join(runtime.GOROOT(), "misc", "wasm", "wasm_exec.js")
	build.OnResolve(esbuild.OnResolveOptions{
		Filter: "./wasm_exec$",
	}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
		return esbuild.OnResolveResult{Path: wasmExecSrcPath}, nil
	})
}

// setupEsbuildWasm generates an esbuild plugin that builds the Tailscale wasm
// binary and serves it as a file that the JS can load.
func setupEsbuildWasm(build esbuild.PluginBuild, dev bool) {
	// Add a resolve hook to convince esbuild that the path exists.
	build.OnResolve(esbuild.OnResolveOptions{
		Filter: "./main.wasm$",
	}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
		return esbuild.OnResolveResult{
			Path:      "./src/main.wasm",
			Namespace: "generated",
		}, nil
	})
	build.OnLoad(esbuild.OnLoadOptions{
		Filter: "./src/main.wasm$",
	}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
		contents, err := buildWasm(dev)
		if err != nil {
			return esbuild.OnLoadResult{}, fmt.Errorf("Cannot build main.wasm: %w", err)
		}
		contentsStr := string(contents)
		return esbuild.OnLoadResult{
			Contents: &contentsStr,
			Loader:   esbuild.LoaderFile,
		}, nil
	})
}

func buildWasm(dev bool) ([]byte, error) {
	start := time.Now()
	outputFile, err := os.CreateTemp("", "main.*.wasm")
	if err != nil {
		return nil, fmt.Errorf("Cannot create main.wasm output file: %w", err)
	}
	outputPath := outputFile.Name()

	defer os.Remove(outputPath)
	// Running defer (*os.File).Close() in defer order before os.Remove
	// because on some systems like Windows, it is possible for os.Remove
	// to fail for unclosed files.
	defer outputFile.Close()

	args := []string{"build", "-tags", "tailscale_go,osusergo,netgo,nethttpomithttp2,omitidna,omitpemdecrypt"}
	if !dev {
		if *devControl != "" {
			return nil, fmt.Errorf("Development control URL can only be used in dev mode.")
		}
		// Omit long paths and debug symbols in release builds, to reduce the
		// generated WASM binary size.
		args = append(args, "-trimpath", "-ldflags", "-s -w")
	} else if *devControl != "" {
		args = append(args, "-ldflags", fmt.Sprintf("-X 'main.ControlURL=%v'", *devControl))
	}

	args = append(args, "-o", outputPath, "./wasm")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("Cannot build main.wasm: %w", err)
	}
	log.Printf("Built wasm in %v\n", time.Since(start).Round(time.Millisecond))

	if !dev {
		err := runWasmOpt(outputPath)
		if err != nil {
			return nil, fmt.Errorf("Cannot run wasm-opt: %w", err)
		}
	}

	return os.ReadFile(outputPath)
}

func runWasmOpt(path string) error {
	start := time.Now()
	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("Cannot stat %v: %w", path, err)
	}
	startSize := stat.Size()
	cmd := exec.Command("../../tool/wasm-opt", "--enable-bulk-memory", "-Oz", path, "-o", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Cannot run wasm-opt: %w", err)
	}
	stat, err = os.Stat(path)
	if err != nil {
		return fmt.Errorf("Cannot stat %v: %w", path, err)
	}
	endSize := stat.Size()
	log.Printf("Ran wasm-opt in %v, size dropped by %dK\n", time.Since(start).Round(time.Millisecond), (startSize-endSize)/1024)
	return nil
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
		Inputs map[string]struct {
			BytesInOutput int64 `json:"bytesInOutput"`
		} `json:"inputs,omitempty"`
		EntryPoint string `json:"entryPoint,omitempty"`
	} `json:"outputs,omitempty"`
}

func setupEsbuildTailwind(build esbuild.PluginBuild, dev bool) {
	build.OnLoad(esbuild.OnLoadOptions{
		Filter: "./src/.*\\.css$",
	}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
		start := time.Now()
		yarnArgs := []string{"--silent", "tailwind", "-i", args.Path}
		if !dev {
			yarnArgs = append(yarnArgs, "--minify")
		}
		cmd := exec.Command(*yarnPath, yarnArgs...)
		tailwindOutput, err := cmd.Output()
		log.Printf("Ran tailwind in %v\n", time.Since(start).Round(time.Millisecond))
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
