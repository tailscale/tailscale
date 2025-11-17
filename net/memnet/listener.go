// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package memnet

import (
	"context"
	"net"
	"strings"
	"sync"
)

const (
	bufferSize = 256 * 1024
)

// Listener is a net.Listener using NewConn to create pairs of network
// connections connected in memory using a buffered pipe. It also provides a
// Dial method to establish new connections.
type Listener struct {
	addr      connAddr
	ch        chan Conn
	closeOnce sync.Once
	closed    chan struct{}
	onClose   func() // or nil

	// NewConn, if non-nil, is called to create a new pair of connections
	// when dialing. If nil, NewConn is used.
	NewConn func(network, addr string, maxBuf int) (Conn, Conn)
}

// Listen returns a new Listener for the provided address.
func Listen(addr string) *Listener {
	return &Listener{
		addr:   connAddr(addr),
		ch:     make(chan Conn),
		closed: make(chan struct{}),
	}
}

// Addr implements net.Listener.Addr.
func (ln *Listener) Addr() net.Addr {
	return ln.addr
}

// Close closes the pipe listener.
func (ln *Listener) Close() error {
	var cleanup func()
	ln.closeOnce.Do(func() {
		cleanup = ln.onClose
		close(ln.closed)
	})
	if cleanup != nil {
		cleanup()
	}
	return nil
}

// Accept blocks until a new connection is available or the listener is closed.
func (ln *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-ln.ch:
		return c, nil
	case <-ln.closed:
		return nil, net.ErrClosed
	}
}

// Dial connects to the listener using the provided context.
// The provided Context must be non-nil. If the context expires before the
// connection is complete, an error is returned. Once successfully connected
// any expiration of the context will not affect the connection.
func (ln *Listener) Dial(ctx context.Context, network, addr string) (_ net.Conn, err error) {
	if !strings.HasSuffix(network, "tcp") {
		return nil, net.UnknownNetworkError(network)
	}
	if connAddr(addr) != ln.addr {
		return nil, &net.AddrError{
			Err:  "invalid address",
			Addr: addr,
		}
	}

	newConn := ln.NewConn
	if newConn == nil {
		newConn = func(network, addr string, maxBuf int) (Conn, Conn) {
			return NewConn(addr, maxBuf)
		}
	}
	c, s := newConn(network, addr, bufferSize)
	defer func() {
		if err != nil {
			c.Close()
			s.Close()
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ln.closed:
		return nil, net.ErrClosed
	case ln.ch <- s:
		return c, nil
	}
}
