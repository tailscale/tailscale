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

	// HandleConn accepts a net.Conn which will be accepted by the Listener.
	// It takes the remoteAddr of the conn in case the supplied net.Conn does
	// not provide the right value for RemoteAddr().
	// Returns an error if the Listener has been closed.
	HandleConn(conn net.Conn, remoteAddr net.Addr) error
}

type connListener struct {
	ch     chan net.Conn
	closed atomic.Bool
}

// New returns a Listener that reports the given addr as its Addr().
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
	return <-l.ch, nil
}

func (l *connListener) Addr() net.Addr {
	return nil
}

func (l *connListener) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return syscall.EINVAL
	}
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
