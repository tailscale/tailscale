// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netx contains types to describe and abstract over how dialing and
// listening are performed.
package netx

import (
	"context"
	"fmt"
	"net"
)

// DialFunc is a function that dials a network address.
//
// It's the type implemented by net.Dialer.DialContext or required
// by net/http.Transport.DialContext, etc.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Network describes a network that can listen and dial. The two common
// implementations are [RealNetwork], using the net package to use the real
// network, or [memnet.Network], using an in-memory network (typically for testing)
type Network interface {
	NewLocalTCPListener() net.Listener
	Listen(network, address string) (net.Listener, error)
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// RealNetwork returns a Network implementation that uses the real
// net package.
func RealNetwork() Network { return realNetwork{} }

// realNetwork implements [Network] using the real net package.
type realNetwork struct{}

func (realNetwork) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (realNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (realNetwork) NewLocalTCPListener() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if ln, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("failed to listen on either IPv4 or IPv6 localhost port: %v", err))
		}
	}
	return ln
}
