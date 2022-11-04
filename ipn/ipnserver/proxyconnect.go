// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js

package ipnserver

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"tailscale.com/logpolicy"
	"tailscale.com/types/logger"
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
func (s *Server) handleProxyConnectConn(ctx context.Context, br *bufio.Reader, c net.Conn, logf logger.Logf) {
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(5 * time.Second)) // should be long enough to send the HTTP headers
	req, err := http.ReadRequest(br)
	if err != nil {
		logf("ReadRequest: %v", err)
		return
	}
	c.SetReadDeadline(time.Time{})

	if req.Method != "CONNECT" {
		logf("ReadRequest: unexpected method %q, not CONNECT", req.Method)
		return
	}

	hostPort := req.RequestURI
	logHost := logpolicy.LogHost()
	allowed := net.JoinHostPort(logHost, "443")
	if hostPort != allowed {
		logf("invalid CONNECT target %q; want %q", hostPort, allowed)
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\nBad CONNECT target.\n")
		return
	}

	tr := logpolicy.NewLogtailTransport(logHost)
	back, err := tr.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		logf("error CONNECT dialing %v: %v", hostPort, err)
		io.WriteString(c, "HTTP/1.1 502 Fail\r\n\r\nConnect failure.\n")
		return
	}
	defer back.Close()

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
