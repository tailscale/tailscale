// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The stund binary is a standalone STUN server.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"tailscale.com/net/stunserver"
	"tailscale.com/tsweb"

	// Support for prometheus varz in tsweb
	_ "tailscale.com/tsweb/promvarz"
)

var (
	stunAddr = flag.String("stun", ":3478", "UDP address on which to start the STUN server")
	httpAddr = flag.String("http", ":3479", "address on which to start the debug http server")
)

func main() {
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("HTTP server listening on %s", *httpAddr)
	go http.ListenAndServe(*httpAddr, mux())

	s := stunserver.New(ctx)
	if err := s.ListenAndServe(*stunAddr); err != nil {
		log.Fatal(err)
	}
}

func mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<h1>stund</h1><a href=/debug>/debug</a>")
	})
	debug := tsweb.Debugger(mux)
	debug.KV("stun_addr", *stunAddr)
	return mux
}
