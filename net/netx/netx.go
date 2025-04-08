// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netx contains the Network type to abstract over either a real
// network or a virtual network for testing.
package netx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"tailscale.com/net/memnet"
)

// Network describes a network that can listen and dial. The two common
// implementations are [RealNetwork], using the net package to use the real
// network, or [MemNetwork], using an in-memory network (typically for testing)
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
			panic(fmt.Sprintf("httptest: failed to listen on a port: %v", err))
		}
	}
	return ln
}

// MemNetwork returns a Network implementation that uses an in-memory
// network for testing. It is only suitable for tests that do not
// require real network access.
//
// As of 2025-04-08, it only supports TCP.
func MemNetwork() Network { return &memNetwork{} }

// memNetwork implements [Network] using an in-memory network.
type memNetwork struct {
	mu  sync.Mutex
	lns map[string]*memnet.Listener // address -> listener
}

func (m *memNetwork) Listen(network, address string) (net.Listener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("memNetwork: Listen called with unsupported network %q", network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("memNetwork: Listen called with invalid address %q: %w", address, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lns == nil {
		m.lns = make(map[string]*memnet.Listener)
	}
	port := ap.Port()
	for {
		if port == 0 {
			port = 33000
		}
		key := net.JoinHostPort(ap.Addr().String(), fmt.Sprint(port))
		_, ok := m.lns[key]
		if ok {
			if ap.Port() != 0 {
				return nil, fmt.Errorf("memNetwork: Listen called with duplicate address %q", address)
			}
			port++
			continue
		}
		ln := memnet.Listen(key)
		m.lns[key] = ln
		return ln, nil
	}
}

func (m *memNetwork) NewLocalTCPListener() net.Listener {
	ln, err := m.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("memNetwork: failed to create local TCP listener: %v", err))
	}
	return ln
}

func (m *memNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("memNetwork: Dial called with unsupported network %q", network)
	}
	m.mu.Lock()
	ln, ok := m.lns[address]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("memNetwork: Dial called on unknown address %q", address)
	}
	return ln.Dial(ctx, network, address)
}
