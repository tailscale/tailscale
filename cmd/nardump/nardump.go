// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// nardump is like nix-store --dump, but in Go, writing a NAR
// file (tar-like, but focused on being reproducible) to stdout
// or to a hash with the --sri flag.
//
// It lets us calculate a Nix sha256 without the person running
// git-pull-oss.sh having Nix available.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"tailscale.com/cmd/nardump/nardump"
)

var sri = flag.Bool("sri", false, "print SRI")

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: nardump <dir>")
	}
	fsys := os.DirFS(flag.Arg(0))
	if *sri {
		s, err := nardump.SRI(fsys)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(s)
		return
	}
	if err := nardump.WriteNAR(os.Stdout, fsys); err != nil {
		log.Fatal(err)
	}
}
