// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// connector-gen is a tool to generate app connector configuration and flags from service provider address data.
package main

import (
	"fmt"
	"os"
)

func help() {
	fmt.Fprintf(os.Stderr, "Usage: %s [help|github|aws] [subcommand-arguments]\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(128)
	}

	switch os.Args[1] {
	case "help", "-h", "--help":
		help()
		os.Exit(0)
	case "github":
		github()
	case "aws":
		aws()
	default:
		help()
		os.Exit(128)
	}
}
