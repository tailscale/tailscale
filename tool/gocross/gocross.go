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
	runtimeDebug "runtime/debug"
)

func main() {
	if len(os.Args) > 1 {
		// These additional subcommands are various support commands to handle
		// integration with Tailscale's existing build system. Unless otherwise
		// specified, these are not stable APIs, and may change or go away at
		// any time.
		switch os.Args[1] {
		case "gocross-version":
			hash, err := embeddedCommit()
			if err != nil {
				fmt.Fprintf(os.Stderr, "getting commit hash: %v", err)
				os.Exit(1)
			}
			fmt.Println(hash)
			os.Exit(0)
		case "is-gocross":
			// This subcommand exits with an error code when called on a
			// regular go binary, so it can be used to detect when `go` is
			// actually gocross.
			os.Exit(0)
		case "make-goroot":
			_, goroot, err := getToolchain()
			if err != nil {
				fmt.Fprintf(os.Stderr, "getting toolchain: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(goroot)
			os.Exit(0)
		case "gocross-get-toolchain-go":
			toolchain, _, err := getToolchain()
			if err != nil {
				fmt.Fprintf(os.Stderr, "getting toolchain: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(filepath.Join(toolchain, "bin/go"))
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

		debug("Input: %s\n", formatArgv(os.Args))
		debug("Command: %s\n", formatArgv(newArgv))
		debug("Set the following flags/envvars:\n%s\n", env.Diff())

		args = newArgv
		if err := env.Apply(); err != nil {
			fmt.Fprintf(os.Stderr, "modifying environment: %v\n", err)
			os.Exit(1)
		}

	}

	doExec(filepath.Join(toolchain, "bin/go"), args, os.Environ())
}

func debug(format string, args ...interface{}) {
	debug := os.Getenv("GOCROSS_DEBUG")
	var (
		out *os.File
		err error
	)
	switch debug {
	case "0", "":
		return
	case "1", "stderr":
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

func embeddedCommit() (string, error) {
	bi, ok := runtimeDebug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("no build info")
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value, nil
		}
	}
	return "", fmt.Errorf("no git commit found")
}
