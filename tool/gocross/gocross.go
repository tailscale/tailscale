// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// gocross is a wrapper around the `go` tool that invokes `go` from Tailscale's
// custom toolchain, with the right build parameters injected based on the
// native+target GOOS/GOARCH.
//
// In short, when aliased to `go`, using `go build`, `go test` behave like the
// upstream Go tools, but produce correctly configured, correctly linked
// binaries stamped with version information.
package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"tailscale.com/atomicfile"
)

func main() {
	if len(os.Args) > 1 {
		// These additional subcommands are various support commands to handle
		// integration with Tailscale's existing build system. Unless otherwise
		// specified, these are not stable APIs, and may change or go away at
		// any time.
		switch os.Args[1] {
		case "gocross-version":
			bi, ok := debug.ReadBuildInfo()
			if !ok {
				fmt.Fprintln(os.Stderr, "failed getting build info")
				os.Exit(1)
			}
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					fmt.Println(s.Value)
					os.Exit(0)
				}
			}
			fmt.Fprintln(os.Stderr, "did not find vcs.revision in build info")
			os.Exit(1)
		case "is-gocross":
			// This subcommand exits with an error code when called on a
			// regular go binary, so it can be used to detect when `go` is
			// actually gocross.
			os.Exit(0)
		case "make-goroot":
			_, gorootDir, err := getToolchain()
			if err != nil {
				fmt.Fprintf(os.Stderr, "getting toolchain: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(gorootDir)
			os.Exit(0)
		case "gocross-get-toolchain-go":
			toolchain, _, err := getToolchain()
			if err != nil {
				fmt.Fprintf(os.Stderr, "getting toolchain: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(filepath.Join(toolchain, "bin/go"))
			os.Exit(0)
		case "gocross-write-wrapper-script":
			if len(os.Args) != 3 {
				fmt.Fprintf(os.Stderr, "usage: gocross write-wrapper-script <path>\n")
				os.Exit(1)
			}
			if err := atomicfile.WriteFile(os.Args[2], wrapperScriptBash, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "writing bash wrapper script: %v\n", err)
				os.Exit(1)
			}
			psFileName := strings.TrimSuffix(os.Args[2], filepath.Ext(os.Args[2])) + ".ps1"
			if err := atomicfile.WriteFile(psFileName, wrapperScriptPowerShell, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "writing PowerShell wrapper script: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	toolchain, goroot, err := getToolchain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getting toolchain: %v\n", err)
		os.Exit(1)
	}

	args := os.Args
	if os.Getenv("GOCROSS_BYPASS") == "" {
		newArgv, env, err := Autoflags(os.Args, goroot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "computing flags: %v\n", err)
			os.Exit(1)
		}

		// Make sure the right version of cmd/go is the first thing in the PATH
		// for tests that execute `go build` or `go test`.
		// TODO: if we really need to do this, do it inside Autoflags, not here.
		path := filepath.Join(toolchain, "bin") + string(os.PathListSeparator) + os.Getenv("PATH")
		env.Set("PATH", path)

		debugf("Input: %s\n", formatArgv(os.Args))
		debugf("Command: %s\n", formatArgv(newArgv))
		debugf("Set the following flags/envvars:\n%s\n", env.Diff())

		args = newArgv
		if err := env.Apply(); err != nil {
			fmt.Fprintf(os.Stderr, "modifying environment: %v\n", err)
			os.Exit(1)
		}

	}

	doExec(filepath.Join(toolchain, "bin/go"), args, os.Environ())
}

//go:embed gocross-wrapper.sh
var wrapperScriptBash []byte

//go:embed gocross-wrapper.ps1
var wrapperScriptPowerShell []byte

func debugf(format string, args ...any) {
	debug := os.Getenv("GOCROSS_DEBUG")
	var (
		out *os.File
		err error
	)
	switch debug {
	case "0", "":
		return
	case "1":
		out = os.Stderr
	default:
		out, err = os.OpenFile(debug, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening debug file %q: %v", debug, err)
			out = os.Stderr
		} else {
			defer out.Close() // May lose some write errors, but we don't care.
		}
	}

	fmt.Fprintf(out, format, args...)
}
