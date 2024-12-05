// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package proxymux splits a net.Listener in two, routing SOCKS5
// connections to one and HTTP requests to the other.
//
// It allows for hosting both a SOCKS5 proxy and an HTTP proxy on the
// same listener.
package proxymux

import (
	"io"
	"net"
	"sync"
	"time"
)

// SplitSOCKSAndHTTP accepts connections on ln and passes connections
// through to either socksListener or httpListener, depending the
// first byte sent by the client.
func SplitSOCKSAndHTTP(ln net.Listener) (socksListener, httpListener net.Listener) {
	sl := &listener{
		addr:   ln.Addr(),
		c:      make(chan net.Conn),
		closed: make(chan struct{}),
	}
	hl := &listener{
		addr:   ln.Addr(),
		c:      make(chan net.Conn),
		closed: make(chan struct{}),
	}

	go splitSOCKSAndHTTPListener(ln, sl, hl)

	return sl, hl
}

func splitSOCKSAndHTTPListener(ln net.Listener, sl, hl *listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			sl.Close()
			hl.Close()
			return
		}
		go routeConn(conn, sl, hl)
	}
}

func routeConn(c net.Conn, socksListener, httpListener *listener) {
	if err := c.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		c.Close()
		return
	}

	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		c.Close()
		return
	}

	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return
	}

	conn := &connWithOneByte{
		Conn: c,
		b:    b[0],
	}

	// First byte of a SOCKS5 session is a version byte set to 5.
	var ln *listener
	if b[0] == 5 {
		ln = socksListener
	} else {
		ln = httpListener
	}
	select {
	case ln.c <- conn:
	case <-ln.closed:
		c.Close()
	}
}

type listener struct {
	addr   net.Addr
	c      chan net.Conn
	mu     sync.Mutex // serializes close() on closed. It's okay to receive on closed without locking.
	closed chan struct{}
}

func (ln *listener) Accept() (net.Conn, error) {
	// Once closed, reliably stay closed, don't race with attempts at
	// further connections.
	select {
	case <-ln.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case ret := <-ln.c:
		return ret, nil
	case <-ln.closed:
		return nil, net.ErrClosed
	}
}

func (ln *listener) Close() error {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	select {
	case <-ln.closed:
		// Already closed
	default:
		close(ln.closed)
	}
	return nil
}

func (ln *listener) Addr() net.Addr {
	return ln.addr
}

// connWithOneByte is a net.Conn that returns b for the first read
// request, then forwards everything else to Conn.
type connWithOneByte struct {
	net.Conn

	b     byte
	bRead bool
}

func (c *connWithOneByte) Read(bs []byte) (int, error) {
	if c.bRead {
		return c.Conn.Read(bs)
	}
	if len(bs) == 0 {
		return 0, nil
	}
	c.bRead = true
	bs[0] = c.b
	return 1, nil
}
