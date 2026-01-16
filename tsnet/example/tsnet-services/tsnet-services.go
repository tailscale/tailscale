// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-services example demonstrates how to use tsnet with Services.
//
// To run this example yourself:
//
//  1. Add access controls which (i) define a new ACL tag, (ii) allow the demo
//     node to host the Service, and (iii) allow peers on the tailnet to reach
//     the Service. A sample ACL policy is provided below.
//
//  2. [Generate an auth key] using the Tailscale admin panel. When doing so, add
//     your new tag to your key (Service hosts must be tagged nodes).
//
//  3. [Define a Service]. For the purposes of this demo, it must be defined to
//     listen on TCP port 443. Note that you only need to follow Step 1 in the
//     linked document.
//
//  4. Run the demo on the command line:
//
//     TS_AUTHKEY=<yourkey> go run tsnet-services.go -service <service-name>
//
// The following is a sample ACL policy for step 1:
//
//	"tagOwners": {
//	   "tag:tsnet-demo-host": ["autogroup:member"],
//	},
//	"autoApprovers": {
//	   "services": {
//	      "svc:tsnet-demo": ["tag:tsnet-demo-host"],
//	   },
//	},
//	"grants": [
//	   "src": ["*"],
//	   "dst": ["svc:tsnet-demo"],
//	   "ip": ["*"],
//	],
//
// [Define a Service]: https://tailscale.com/kb/1552/tailscale-services#step-1-define-a-tailscale-service
// [Generate an auth key]: https://tailscale.com/kb/1085/auth-keys#generate-an-auth-key
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"tailscale.com/tsnet"
)

var (
	svcName = flag.String("service", "", "the name of your Service, e.g. svc:tsnet-demo")
)

func main() {
	flag.Parse()
	if *svcName == "" {
		log.Fatal("a Service name must be provided")
	}

	s := &tsnet.Server{
		Hostname: "tsnet-services-demo",
	}
	defer s.Close()

	ln, err := s.ListenService(*svcName, tsnet.ServiceModeHTTP{
		HTTPS: true,
		Port:  443,
	})
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
