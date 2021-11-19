// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
)

func envOr(name, def string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}

	return def
}

var (
	bind     = flag.String("bind", ":443", "TCP hostport to bind to for TLS http traffic")
	hostname = flag.String("hostname", envOr("HOSTNAME", "toolname"), "hostname to register on tailnet (can be set with $HOSTNAME)")
	auth     = flag.Bool("auth", false, "if set, authenticate with tailscale (enables verbose logging)")
	v        = flag.Bool("v", false, "if set, enable verbose tailscale logs")
	to       = flag.String("to", envOr("TO", "http://127.0.0.1:3030"), "HTTP/S url to reverse proxy to (can be set with $TO)")
)

func main() {
	os.Setenv("TAILSCALE_USE_WIP_CODE", "true")
	flag.Parse()

	srv := tsnet.Server{
		Hostname: *hostname,
	}

	if *auth || *v {
		srv.Logf = log.Printf
	} else {
		srv.Logf = func(string, ...interface{}) {}
	}

	if *auth {
		os.Setenv("TS_LOGIN", "1")
	}

	ln, err := srv.Listen("tcp", *bind)
	if err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(*to)
	if err != nil {
		log.Fatalf("%s wasn't a valid URL: %v", *to, err)
	}

	h := httputil.NewSingleHostReverseProxy(u)

	ln = tls.NewListener(ln, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tailscale.GetCertificate(chi)
			if err != nil {
				log.Println(err)
			}
			return c, err
		},
	})

	s := &http.Server{
		IdleTimeout: 5 * time.Minute,
		Addr:        *bind,
		Handler:     h,
	}

	log.Printf("listening for https on https://%s.your.tailcert.domain and forwarding to %s", *hostname, *to)

	log.Fatal(s.Serve(ln))
}
