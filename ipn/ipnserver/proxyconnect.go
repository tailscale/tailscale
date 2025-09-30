// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package ipnserver

import (
	"io"
	"net"
	"net/http"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/logpolicy"
)

// handleProxyConnectConn handles a CONNECT request to
// log.tailscale.com (or whatever the configured log server is). This
// is intended for use by the Windows GUI client to log via when an
// exit node is in use, so the logs don't go out via the exit node and
// instead go directly, like tailscaled's. The dialer tried to do that
// in the unprivileged GUI by binding to a specific interface, but the
// "Internet Kill Switch" installed by tailscaled for exit nodes
// precludes that from working and instead the GUI fails to dial out.
// So, go through tailscaled (with a CONNECT request) instead.
func (s *Server) handleProxyConnectConn(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasOutboundProxy {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	ctx := r.Context()
	if r.Method != "CONNECT" {
		panic("[unexpected] miswired")
	}

	hostPort := r.RequestURI
	logHost := logpolicy.LogHost()
	allowed := net.JoinHostPort(logHost, "443")
	if hostPort != allowed {
		s.logf("invalid CONNECT target %q; want %q", hostPort, allowed)
		http.Error(w, "Bad CONNECT target.", http.StatusForbidden)
		return
	}

	dialContext := logpolicy.MakeDialFunc(s.netMon, s.logf)
	back, err := dialContext(ctx, "tcp", hostPort)
	if err != nil {
		s.logf("error CONNECT dialing %v: %v", hostPort, err)
		http.Error(w, "Connect failure", http.StatusBadGateway)
		return
	}
	defer back.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT hijack unavailable", http.StatusInternalServerError)
		return
	}
	c, br, err := hj.Hijack()
	if err != nil {
		s.logf("CONNECT hijack: %v", err)
		return
	}
	defer c.Close()

	io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, back)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(back, br)
		errc <- err
	}()
	<-errc
}
