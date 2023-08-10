// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The web-client command demonstrates serving the Tailscale web client over tsnet.
package main

import (
	"flag"
	"log"
	"net/http"

	"tailscale.com/client/web"
	"tailscale.com/tsnet"
)

var (
	devMode = flag.Bool("dev", false, "run web client in dev mode")
)

func main() {
	flag.Parse()

	s := new(tsnet.Server)
	defer s.Close()

	ln, err := s.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	// Serve the Tailscale web client.
	ws := web.NewServer(*devMode, lc)
	if err := http.Serve(ln, ws); err != nil {
		if err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
}
