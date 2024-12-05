// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet_test

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"

	"tailscale.com/tsnet"
)

func firstLabel(s string) string {
	s, _, _ = strings.Cut(s, ".")
	return s
}

// Example_tshello is a full example on using tsnet. When you run this program it will print
// an authentication link. Open it in your favorite web browser and add it to your tailnet
// like any other machine. Open another terminal window and try to ping it:
//
//	$ ping tshello -c 2
//	PING tshello (100.105.183.159) 56(84) bytes of data.
//	64 bytes from tshello.your-tailnet.ts.net (100.105.183.159): icmp_seq=1 ttl=64 time=25.0 ms
//	64 bytes from tshello.your-tailnet.ts.net (100.105.183.159): icmp_seq=2 ttl=64 time=1.12 ms
//
// Then connect to it using curl:
//
//	$ curl http://tshello
//	<html><body><h1>Hello, world!</h1>
//	<p>You are <b>Xe</b> from <b>pneuma</b> (100.78.40.86:49214)</p>
//
// From here you can do anything you want with the Go standard library HTTP stack, or anything
// that is compatible with it (Gin/Gonic, Gorilla/mux, etc.).
func Example_tshello() {
	var (
		addr     = flag.String("addr", ":80", "address to listen on")
		hostname = flag.String("hostname", "tshello", "hostname to use on the tailnet")
	)

	flag.Parse()
	s := new(tsnet.Server)
	s.Hostname = *hostname
	defer s.Close()
	ln, err := s.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello, tailnet!</h1>\n")
		fmt.Fprintf(w, "<p>You are <b>%s</b> from <b>%s</b> (%s)</p>",
			html.EscapeString(who.UserProfile.LoginName),
			html.EscapeString(firstLabel(who.Node.ComputedName)),
			r.RemoteAddr)
	})))
}
