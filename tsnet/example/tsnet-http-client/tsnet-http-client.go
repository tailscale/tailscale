// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tshello server demonstrates how to use Tailscale as a library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"tailscale.com/tsnet"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <url in tailnet>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
	}
	tailnetURL := flag.Arg(0)

	s := new(tsnet.Server)
	defer s.Close()

	if err := s.Start(); err != nil {
		log.Fatal(err)
	}

	cli := s.HTTPClient()

	resp, err := cli.Get(tailnetURL)
	if err != nil {
		log.Fatal(err)
	}

	resp.Write(os.Stdout)
}
