// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nettest contains additional test helpers related to network state
// that can't go into tstest for circular dependency reasons.
package nettest

import (
	"context"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netx"
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

// PreferMemNetwork reports whether the --use-test-memnet flag is set.
func PreferMemNetwork() bool {
	return *useMemNet
}

// GetNetwork returns the appropriate Network implementation based on
// whether the --use-test-memnet flag is set.
//
// Each call generates a new network.
func GetNetwork(tb testing.TB) netx.Network {
	var n netx.Network
	if PreferMemNetwork() {
		n = &memnet.Network{}
	} else {
		n = netx.RealNetwork()
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

// NewHTTPServer starts and returns a new [httptest.Server].
// The caller should call Close when finished, to shut it down.
func NewHTTPServer(net netx.Network, handler http.Handler) *httptest.Server {
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
func NewUnstartedHTTPServer(nw netx.Network, handler http.Handler) *httptest.Server {
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
