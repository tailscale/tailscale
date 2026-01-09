// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-services example demonstrates how to use tsnet with Services.
//
// To run this example yourself:
//
//  1. Define an ACL tag, an auto-approval rule, and traffic permits by adding
//     the following to your tailnet's ACL policy file:
//     TODO: convince gofmt to chill
//     "tagOwners": {
//     "tag:tsnet-demo-host": ["autogroup:member"],
//     },
//     "autoApprovers": {
//     "services": {
//     "svc:tsnet-demo": ["tag:tsnet-demo-host"],
//     },
//     },
//     // Allow anybody in the tailnet to reach the demo Service.
//     "grants": [
//     "src": ["*"],
//     "dst": ["tag:tsnet-demo-host"],
//     "ip": ["*"],
//     ],
//
//  2. Generate an auth key using the Tailscale admin panel. When doing so, add
//     the tsnet-demo-host tag to your key.
//     https://tailscale.com/kb/1085/auth-keys#generate-an-auth-key
//
//  2. Define a Service. For the purposes of this demo, it must be defined to
//     listen on TCP port 443. Note that you only need to follow Step 1 in the
//     following document.
//     https://tailscale.com/kb/1552/tailscale-services#step-1-define-a-tailscale-service
//
//  3. Run the demo on the command line:
//     TS_AUTHKEY=<yourkey> go run tsnet-services.go -service <service-name>
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
