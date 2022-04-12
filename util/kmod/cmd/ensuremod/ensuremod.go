// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"

	"tailscale.com/util/kmod"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "error: a module name must be supplied")
		os.Exit(1)
	}

	done, err := kmod.EnsureModule(os.Args[1])
	if done {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	os.Exit(1)
}
