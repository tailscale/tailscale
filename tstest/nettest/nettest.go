// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nettest contains additional test helpers related to network state
// that can't go into tstest for circular dependency reasons.
package nettest

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/util/testenv"
)

var useMemNet = flag.Bool("use-test-memnet", false, "prefer using in-memory network for tests")

// SkipIfNoNetwork skips the test if it looks like there's no network
// access.
func SkipIfNoNetwork(t testing.TB) {
	nm := netmon.NewStatic()
	if !nm.InterfaceState().AnyInterfaceUp() {
		t.Skip("skipping; test requires network but no interface is up")
	}
}

// Network is an interface for use in tests that describes either [RealNetwork]
// or [MemNetwork].
type Network interface {
	NewLocalTCPListener() net.Listener
	Listen(network, address string) (net.Listener, error)
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// PreferMemNetwork reports whether the --use-test-memnet flag is set.
func PreferMemNetwork() bool {
	return *useMemNet
}

// GetNetwork returns the appropriate Network implementation based on
// whether the --use-test-memnet flag is set.
//
// Each call generates a new network.
func GetNetwork(tb testing.TB) Network {
	var n Network
	if PreferMemNetwork() {
		n = MemNetwork()
	} else {
		n = RealNetwork()
	}

	detectLeaks := PreferMemNetwork() || !testenv.InParallelTest(tb)
	if detectLeaks {
		tb.Cleanup(func() {
			// TODO: leak detection, making sure no connections
			// remain at the end of the test. For real network,
			// snapshot conns in pid table before & after.
		})
	}
	return n
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

// NewHTTPServer starts and returns a new [httptest.Server].
// The caller should call Close when finished, to shut it down.
func NewHTTPServer(net Network, handler http.Handler) *httptest.Server {
	ts := NewUnstartedHTTPServer(net, handler)
	ts.Start()
	return ts
}

// NewUnstartedHTTPServer returns a new [httptest.Server] but doesn't start it.
//
// After changing its configuration, the caller should call Start or
// StartTLS.
//
// The caller should call Close when finished, to shut it down.
func NewUnstartedHTTPServer(nw Network, handler http.Handler) *httptest.Server {
	s := &httptest.Server{
		Config: &http.Server{Handler: handler},
	}
	ln := nw.NewLocalTCPListener()
	s.Listener = &listenerOnAddrOnce{
		Listener: ln,
		fn: func() {
			c := s.Client()
			if c == nil {
				// This httptest.Server.Start initialization order has been true
				// for over 10 years. Let's keep counting on it.
				panic("httptest.Server: Client not initialized before Addr called")
			}
			if c.Transport == nil {
				c.Transport = &http.Transport{}
			}
			tr := c.Transport.(*http.Transport)
			if tr.Dial != nil || tr.DialContext != nil {
				panic("unexpected non-nil Dial or DialContext in httptest.Server.Client.Transport")
			}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nw.Dial(ctx, network, addr)
			}
		},
	}
	return s
}

// listenerOnAddrOnce is a net.Listener that wraps another net.Listener
// and calls a function the first time its Addr is called.
type listenerOnAddrOnce struct {
	net.Listener
	once sync.Once
	fn   func()
}

func (ln *listenerOnAddrOnce) Addr() net.Addr {
	ln.once.Do(func() {
		ln.fn()
	})
	return ln.Listener.Addr()
}
