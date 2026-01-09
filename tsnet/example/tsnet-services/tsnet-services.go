// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-services example demonstrates how to use tsnet with Services.
// TODO:
//   - explain that a Service must be defined for the tailent and link to KB on
//     defining a Service
//   - recommend using an auth key with associated tags
//   - recommend an auto-approval rule for service tags
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

	"tailscale.com/tsnet"
)

var (
	svcName = flag.String("service", "", "the name of your Service, e.g. svc:demo-service")
)

// TODO: this worked several times, then my host got stuck in 'Partially configured: has-config, config-valid'

func main() {
	flag.Parse()
	if *svcName == "" {
		log.Fatal("a Service name must be provided")
	}

	const port uint16 = 443

	s := &tsnet.Server{
		Dir:      "./services-demo-config",
		Hostname: "tsnet-services-demo",
	}
	defer s.Close()

	ln, err := s.ListenService(*svcName, port, tsnet.ServiceHTTPOptions{HTTPS: true})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("Listening on https://%v\n", ln.FQDN)

	err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "<html><body><h1>Hello, tailnet!</h1>")
	}))
	log.Fatal(err)
}
