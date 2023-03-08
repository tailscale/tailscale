// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

// HTTP proxy code

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"tailscale.com/net/httpconnect"
)

// httpProxyHandler returns an HTTP proxy http.Handler using the
// provided backend dialer.
func httpProxyHandler(dialer func(ctx context.Context, netw, addr string) (net.Conn, error)) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {}, // no change
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}
	connect := &httpconnect.Connect{
		Dialer: dialer,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			backURL := r.RequestURI
			if strings.HasPrefix(backURL, "/") || backURL == "*" {
				http.Error(w, "bogus RequestURI; must be absolute URL or CONNECT", 400)
				return
			}
			rp.ServeHTTP(w, r)
			return
		}
		connect.Handle(w, r)
	})
}
