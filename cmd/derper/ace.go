// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO: docs about all this

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/connectproxy"
)

// serveConnect handles a CONNECT request for ACE support.
func serveConnect(s *derpserver.Server, w http.ResponseWriter, r *http.Request) {
	if !*flagACEEnabled {
		http.Error(w, "CONNECT not enabled", http.StatusForbidden)
		return
	}
	if r.TLS == nil {
		// This should already be enforced by the caller of serveConnect, but
		// double check.
		http.Error(w, "CONNECT requires TLS", http.StatusForbidden)
		return
	}

	ch := &connectproxy.Handler{
		Check: func(hostPort string) error {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				return err
			}
			if port != "443" && port != "80" {
				// There are only two types of CONNECT requests the client makes
				// via ACE: requests for /key (port 443) and requests to upgrade
				// to the bidirectional ts2021 Noise protocol.
				//
				// The ts2021 layer can bootstrap over port 80 (http) or port
				// 443 (https).
				//
				// Without ACE, we prefer port 80 to avoid unnecessary double
				// encryption. But enough places require TLS+port 443 that we do
				// support that double encryption path as a fallback.
				//
				// But ACE adds its own TLS layer (ACE is always CONNECT over
				// https). If we don't permit port 80 here as a target, we'd
				// have three layers of encryption (TLS + TLS + Noise) which is
				// even more silly than two.
				//
				// So we permit port 80 such that we can only have two layers of
				// encryption, varying by the request type:
				//
				//  1. TLS from client to ACE proxy (CONNECT)
				//  2a. TLS from ACE proxy to https://controlplane.tailscale.com/key (port 443)
				//  2b. ts2021 Noise from ACE proxy to http://controlplane.tailscale.com/ts2021 (port 80)
				//
				// But nothing's stopping the client from doing its ts2021
				// upgrade over https anyway and having three layers of
				// encryption. But we can at least permit the client to do a
				// "CONNECT controlplane.tailscale.com:80 HTTP/1.1" if it wants.
				return fmt.Errorf("only ports 443 and 80 are allowed")
			}
			// TODO(bradfitz): make policy configurable from flags and/or come
			// from local tailscaled nodeAttrs
			if !strings.HasSuffix(host, ".tailscale.com") || strings.Contains(host, "derp") {
				return errors.New("bad host")
			}
			return nil
		},
	}
	ch.ServeHTTP(w, r)
}
