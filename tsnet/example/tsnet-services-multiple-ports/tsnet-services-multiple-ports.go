// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-services example demonstrates how to use tsnet with Services.
// TODO:
//   - explain that a Service must be defined for the tailent and link to KB on
//     defining a Service
//   - recommend using an auth key with associated tags
//   - recommend an auto-approval rule for service tags
//
// TODO: can we provide example ACL which only allows certain user groups to hit
// the pprof port?
//
// To use it, generate an auth key from the Tailscale admin panel and
// run the demo with the key:
//
//	TS_AUTHKEY=<yourkey> go run tsnet-services.go -service <service-name>
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"strings"

	"tailscale.com/tsnet"
)

var (
	svcName = flag.String("service", "", "the name of your Service, e.g. svc:demo-service")
)

func main() {
	flag.Parse()
	if *svcName == "" {
		log.Fatal("a Service name must be provided")
	}

	const serverPort uint16 = 443
	const pprofPort uint16 = 6060

	s := &tsnet.Server{
		Dir:      "./services-demo-config",
		Hostname: "tsnet-services-demo",
	}
	defer s.Close()

	ln, err := s.ListenService(*svcName, serverPort, tsnet.ServiceHTTPOptions{HTTPS: true})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	pprofLn, err := s.ListenService(*svcName, pprofPort, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer pprofLn.Close()

	go func() {
		log.Printf("Listening for pprof requests on http://%v:%d\n", pprofLn.FQDN, pprofPort)

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
	err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><body><h1>Hello, tailnet!</h1>")
	}))
	log.Fatal(err)
}
