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

	"tailscale.com/derp"
	"tailscale.com/net/connectproxy"
)

// serveConnect handles a CONNECT request for ACE support.
func serveConnect(s *derp.Server, w http.ResponseWriter, r *http.Request) {
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
			if port != "443" {
				return fmt.Errorf("only port 443 is allowed")
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
