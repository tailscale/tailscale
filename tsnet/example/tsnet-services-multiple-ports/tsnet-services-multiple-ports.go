// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-services example demonstrates how to use tsnet with Services
// which listen on multiple ports.
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
//     listen on TCP ports 443 and 6060. Note that you only need to follow Step
//     1 in the following document.
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
