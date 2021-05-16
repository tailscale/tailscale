// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tshello server demonstrates how to use Tailscale as a library.
package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"

	"tailscale.com/tsnet"
)

func main() {
	s := new(tsnet.Server)
	ln, err := s.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := s.WhoIs(r.RemoteAddr)
		if !ok {
			http.Error(w, "WhoIs failed", 500)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello, world!</h1>\n")
		fmt.Fprintf(w, "<p>You are <b>%s</b> from <b>%s</b> (%s)</p>",
			html.EscapeString(who.UserProfile.LoginName),
			html.EscapeString(firstLabel(who.Node.ComputedName)),
			r.RemoteAddr)
	})))
}

func firstLabel(s string) string {
	if i := strings.Index(s, "."); i != -1 {
		return s[:i]
	}
	return s
}
