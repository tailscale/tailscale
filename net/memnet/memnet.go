// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package memnet implements an in-memory network implementation.
// It is useful for dialing and listening on in-memory addresses
// in tests and other situations where you don't want to use the
// network.
package memnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"tailscale.com/net/netx"
)

var _ netx.Network = (*Network)(nil)

// Network implements [Network] using an in-memory network, usually
// used for testing.
//
// As of 2025-04-08, it only supports TCP.
//
// Its zero value is a valid [netx.Network] implementation.
type Network struct {
	mu  sync.Mutex
	lns map[string]*Listener // address -> listener
}

func (m *Network) Listen(network, address string) (net.Listener, error) {
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
		m.lns = make(map[string]*Listener)
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
		ln := Listen(key)
		m.lns[key] = ln
		ln.onClose = func() {
			m.mu.Lock()
			delete(m.lns, key)
			m.mu.Unlock()
		}
		return ln, nil
	}
}

func (m *Network) NewLocalTCPListener() net.Listener {
	ln, err := m.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("memNetwork: failed to create local TCP listener: %v", err))
	}
	return ln
}

func (m *Network) Dial(ctx context.Context, network, address string) (net.Conn, error) {
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
