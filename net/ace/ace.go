// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ace implements a Dialer that dials via a Tailscale ACE (CONNECT)
// proxy.
//
// TODO: document this more, when it's more done. As of 2025-09-17, it's in
// development.
package ace

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
)

// Dialer is an HTTP CONNECT proxy dialer to dial the control plane via an ACE
// proxy.
type Dialer struct {
	ACEHost   string
	ACEHostIP netip.Addr // optional; if non-zero, use this IP instead of DNS
	ACEPort   int        // zero means 443

	// NetDialer optionally specifies the underlying dialer to use to reach the
	// ACEHost. If nil, net.Dialer.DialContext is used.
	NetDialer func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *Dialer) netDialer() func(ctx context.Context, network, address string) (net.Conn, error) {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	var std net.Dialer
	return std.DialContext
}

func (d *Dialer) acePort() int { return cmp.Or(d.ACEPort, 443) }

func (d *Dialer) Dial(ctx context.Context, network, address string) (_ net.Conn, err error) {
	if network != "tcp" {
		return nil, errors.New("only TCP is supported")
	}

	var targetHost string
	if d.ACEHostIP.IsValid() {
		targetHost = d.ACEHostIP.String()
	} else {
		targetHost = d.ACEHost
	}

	cc, err := d.netDialer()(ctx, "tcp", net.JoinHostPort(targetHost, fmt.Sprint(d.acePort())))
	if err != nil {
		return nil, err
	}

	// Now that we've dialed, we're about to do three potentially blocking
	// operations: the TLS handshake, the CONNECT write, and the HTTP response
	// read. To make our context work over all that, we use a context.AfterFunc
	// to start a goroutine that'll tear down the underlying connection if the
	// context expires.
	//
	// To prevent races, we use an atomic.Bool to guard access to the underlying
	// connection being either good or bad. Only one goroutine (the success path
	// in this goroutine after the ReadResponse or the AfterFunc's failure
	// goroutine) will compare-and-swap it from false to true.
	var done atomic.Bool
	stop := context.AfterFunc(ctx, func() {
		if done.CompareAndSwap(false, true) {
			cc.Close()
		}
	})
	defer func() {
		if err != nil {
			if ctx.Err() != nil {
				// Prefer the context error. The other error is likely a side
				// effect of the context expiring and our tearing down of the
				// underlying connection, and is thus probably something like
				// "use of closed network connection", which isn't useful (and
				// actually misleading) for the caller.
				err = ctx.Err()
			}
			stop()
			cc.Close()
		}
	}()

	tc := tls.Client(cc, &tls.Config{ServerName: d.ACEHost})
	if err := tc.Handshake(); err != nil {
		return nil, err
	}

	// TODO(tailscale/corp#32484): send proxy-auth header
	if _, err := fmt.Fprintf(tc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, d.ACEHost); err != nil {
		return nil, err
	}

	br := bufio.NewReader(tc)
	connRes, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}

	// Now that we're done with blocking operations, mark the connection
	// as good, to prevent the context's AfterFunc from closing it.
	if !stop() || !done.CompareAndSwap(false, true) {
		// We lost a race and the context expired.
		return nil, ctx.Err()
	}

	if connRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ACE CONNECT response: %s", connRes.Status)
	}

	if br.Buffered() > 0 {
		return nil, fmt.Errorf("unexpected %d bytes of buffered data after ACE CONNECT", br.Buffered())
	}
	return tc, nil
}
