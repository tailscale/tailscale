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
	addr    = flag.String("addr", "localhost:8060", "address of Tailscale web client")
	devMode = flag.Bool("dev", false, "run web client in dev mode")
)

func main() {
	flag.Parse()

	s := new(tsnet.Server)
	defer s.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	// Serve the Tailscale web client.
	ws, err := web.NewServer(web.ServerOpts{
		DevMode:     *devMode,
		LocalClient: lc,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Shutdown()
	log.Printf("Serving Tailscale web client on http://%s", *addr)
	if err := http.ListenAndServe(*addr, ws); err != nil {
		if err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
}
