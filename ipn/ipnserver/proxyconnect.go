// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package ipnserver

import (
	"net"
	"net/http"

	"tailscale.com/logpolicy"
	"tailscale.com/net/httpconnect"
)

// handleProxyConnectConn handles a CONNECT request to
// log.tailscale.io (or whatever the configured log server is). This
// is intended for use by the Windows GUI client to log via when an
// exit node is in use, so the logs don't go out via the exit node and
// instead go directly, like tailscaled's. The dialer tried to do that
// in the unprivileged GUI by binding to a specific interface, but the
// "Internet Kill Switch" installed by tailscaled for exit nodes
// precludes that from working and instead the GUI fails to dial out.
// So, go through tailscaled (with a CONNECT request) instead.
func (s *Server) handleProxyConnectConn(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		panic("[unexpected] miswired")
	}
	logHost := logpolicy.LogHost()
	connect := &httpconnect.Connect{
		Dialer:     logpolicy.NewLogtailTransport(logHost).DialContext,
		AllowedURI: net.JoinHostPort(logHost, "443"),
	}
	connect.Handle(w, r)
}
