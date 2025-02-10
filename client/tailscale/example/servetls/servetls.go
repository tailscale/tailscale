// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The servetls program shows how to run an HTTPS server
// using a Tailscale cert via LetsEncrypt.
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"

	"tailscale.com/client/local"
)

func main() {
	var lc local.Client
	s := &http.Server{
		TLSConfig: &tls.Config{
			GetCertificate: lc.GetCertificate,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<h1>Hello from Tailscale!</h1> It works.")
		}),
	}
	log.Printf("Running TLS server on :443 ...")
	log.Fatal(s.ListenAndServeTLS("", ""))
}
