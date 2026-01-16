// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet_test

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"strings"

	"tailscale.com/tsnet"
)

// This example function is in a separate file for the "net/http/pprof" import.

// ExampleServer_ListenService_multiplePorts demonstrates how to advertise a
// Service on multiple ports. In this example, we run an HTTPS server on 443 and
// an HTTP server handling pprof requests to the same runtime on 6060.
func ExampleServer_ListenService_multiplePorts() {
	s := &tsnet.Server{
		Hostname: "tsnet-services-demo",
	}
	defer s.Close()

	ln, err := s.ListenService("svc:my-service", tsnet.ServiceModeHTTP{
		HTTPS: true,
		Port:  443,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	pprofLn, err := s.ListenService("svc:my-service", tsnet.ServiceModeTCP{
		Port: 6060,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer pprofLn.Close()

	go func() {
		log.Printf("Listening for pprof requests on http://%v:%d\n", pprofLn.FQDN, 6060)

		handler := func(w http.ResponseWriter, r *http.Request) {
			// The pprof listener is separate from our main server, so we can
			// allow users to leave off the /debug/pprof prefix. We'll just
			// attach it here, then pass along to the pprof handlers, which have
			// been added implicitly due to our import of net/http/pprof.
			if !strings.HasPrefix("/debug/pprof", r.URL.Path) {
				r.URL.Path = "/debug/pprof" + r.URL.Path
			}
			http.DefaultServeMux.ServeHTTP(w, r)
		}
		if err := http.Serve(pprofLn, http.HandlerFunc(handler)); err != nil {
			log.Fatal("error serving pprof:", err)
		}
	}()

	log.Printf("Listening on https://%v\n", ln.FQDN)

	// Specifying a handler here means pprof endpoints will not be served by
	// this server (since we are not using http.DefaultServeMux).
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><body><h1>Hello, tailnet!</h1>")
	})))
}
