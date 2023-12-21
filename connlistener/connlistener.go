// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package connlistener provides a net.Listener to which one can hand
// connections directly.
package connlistener

import (
	"net"
	"sync/atomic"
	"syscall"
)

// Listener is a net.Listener to which one can manually hand new connections
// using the HandleConn() method.
type Listener interface {
	net.Listener

	// HandleConn makes the specified conn available to callers of this
	// Listener's Accept() function. It takes the remoteAddr of the conn in
	// case the supplied net.Conn does not provide the right value for
	// RemoteAddr(). This method returns an error if the Listener has been
	// closed.
	HandleConn(conn net.Conn, remoteAddr net.Addr) error
}

type connListener struct {
	ch     chan net.Conn
	closed atomic.Bool
}

// New creates a Listener.
func New() Listener {
	return &connListener{
		ch: make(chan net.Conn, 10), // we use a small buffer to avoid blocking callers to ConnAvailable
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		// TODO(oxtoacart): make this error match what a regular net.Listener does
		return nil, syscall.EINVAL
	}
	conn, ok := <-l.ch
	if !ok {
		return nil, syscall.EINVAL
	}
	return conn, nil
}

func (l *connListener) Addr() net.Addr {
	return nil
}

func (l *connListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return syscall.EINVAL
	}
	close(l.ch)
	return nil
}

func (l *connListener) HandleConn(c net.Conn, remoteAddr net.Addr) error {
	if l.closed.Load() {
		return syscall.EINVAL
	}
	l.ch <- &connWithRemoteAddr{Conn: c, remoteAddr: remoteAddr}
	return nil
}

type connWithRemoteAddr struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connWithRemoteAddr) RemoteAddr() net.Addr {
	return c.remoteAddr
}
