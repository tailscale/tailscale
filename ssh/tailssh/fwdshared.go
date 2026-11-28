// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || windows

// The forwarding helpers shared by the platforms whose tailssh dials and
// binds forwarded TCP sockets itself, rather than through gliderssh's
// default handlers: the unix monitor platforms and Windows. plan9 keeps
// gliderssh's handlers and does not build this file. These helpers are
// identity-independent; the per-platform files decide whose credentials
// the dial or bind runs under.

package tailssh

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"tailscale.com/envknob"
)

// sshForwardGatewayPorts permits reverse TCP forwards to bind
// non-loopback addresses. It is the equivalent of sshd's GatewayPorts.
var sshForwardGatewayPorts = envknob.RegisterBool("TS_SSH_FORWARD_GATEWAY_PORTS")

// fwdRelayCloseDrainTimeout bounds delivery of queued client payload after a
// full close. A service that stops reading must not retain the relay forever.
const fwdRelayCloseDrainTimeout = 5 * time.Second

// The remote-forward request and channel payloads of RFC 4254 §7.
type fwdRemoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type fwdRemoteForwardSuccess struct {
	BindPort uint32
}

type fwdRemoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type fwdRemoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// fwdLoopbackBindAddr reports the bind address to use for a reverse TCP
// forward and whether the requested one is permitted. Only loopback is
// allowed, 127.0.0.0/8 and ::1, unless TS_SSH_FORWARD_GATEWAY_PORTS is
// set. An empty address binds 127.0.0.1. The listener resolves
// "localhost".
func fwdLoopbackBindAddr(bindAddr string) (string, bool) {
	if sshForwardGatewayPorts() {
		return bindAddr, true
	}
	switch bindAddr {
	case "":
		// ssh(1) documents -R without an address as binding loopback. Bind
		// it explicitly so the listener is unambiguous.
		return "127.0.0.1", true
	case "localhost":
		return bindAddr, true
	}
	if ip := net.ParseIP(bindAddr); ip != nil && ip.IsLoopback() {
		return bindAddr, true
	}
	return "", false
}

// fwdAcceptAndBicopy owns dconn, accepting the channel and copying data until
// completion or closure. Channel EOF permits a response; full channel closure
// stops waiting for the service while allowing buffered client payload to drain.
func fwdAcceptAndBicopy(ctx context.Context, newChan gossh.NewChannel, dconn net.Conn) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go func() {
		gossh.DiscardRequests(reqs)
		// CHANNEL_CLOSE ends service output, but the channel may still
		// have buffered client payload to drain. Bound that final write
		// rather than canceling both copy directions and losing the data.
		dconn.SetWriteDeadline(time.Now().Add(fwdRelayCloseDrainTimeout))
		dconn.SetReadDeadline(time.Now())
	}()
	fwdBicopy(ctx, ch, dconn)
}

// fwdBicopy copies data bidirectionally between c1 and c2 until both
// directions complete or the context is canceled, half-closing the write
// side of each destination on EOF (RFC 4254 §5.3).
func fwdBicopy(ctx context.Context, c1, c2 io.ReadWriteCloser) {
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		defer fwdHalfCloseWrite(c1)
		_, _ = io.Copy(c1, c2)
	})
	wg.Go(func() {
		defer fwdHalfCloseWrite(c2)
		_, _ = io.Copy(c2, c1)
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-ctx.Done():
		c1.Close()
		c2.Close()
		<-done
	}
}

// fwdHalfCloseWrite signals EOF on the write side of c if c supports
// CloseWrite, as *net.TCPConn, *net.UnixConn, and gossh.Channel do.
// Otherwise the deferred full Close in fwdBicopy handles cleanup.
func fwdHalfCloseWrite(c io.ReadWriteCloser) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
