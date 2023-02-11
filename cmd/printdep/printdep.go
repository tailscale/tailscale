// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The printdep command is a build system tool for printing out information
// about dependencies.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"

	ts "tailscale.com"
)

var (
	goToolchain    = flag.Bool("go", false, "print the supported Go toolchain git hash (a github.com/tailscale/go commit)")
	goToolchainURL = flag.Bool("go-url", false, "print the URL to the tarball of the Tailscale Go toolchain")
	alpine         = flag.Bool("alpine", false, "print the tag of alpine docker image")
)

func main() {
	flag.Parse()
	if *alpine {
		fmt.Println(strings.TrimSpace(ts.AlpineDockerTag))
		return
	}
	if *goToolchain {
		fmt.Println(strings.TrimSpace(ts.GoToolchainRev))
	}
	if *goToolchainURL {
		switch runtime.GOOS {
		case "linux", "darwin":
		default:
			log.Fatalf("unsupported GOOS %q", runtime.GOOS)
		}
		fmt.Printf("https://github.com/tailscale/go/releases/download/build-%s/%s-%s.tar.gz\n", strings.TrimSpace(ts.GoToolchainRev), runtime.GOOS, runtime.GOARCH)
	}
}
