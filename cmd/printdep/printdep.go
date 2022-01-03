// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The printdep command is a build system tool for printing out information
// about dependencies.
package main

import (
	"flag"
	"fmt"
	"strings"

	ts "tailscale.com"
)

var (
	goToolchain = flag.Bool("go", false, "print the supported Go toolchain git hash (a github.com/tailscale/go commit)")
)

func main() {
	flag.Parse()
	if *goToolchain {
		fmt.Println(strings.TrimSpace(ts.GoToolchainRev))
	}
}
