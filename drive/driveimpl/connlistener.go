// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"log"
	"net"
	"sync"
	"syscall"
)

type connListener struct {
	ch       chan net.Conn
	closedCh chan any
	closeMu  sync.Mutex
}

// newConnListener creates a net.Listener to which one can hand connections
// directly.
func newConnListener() *connListener {
	return &connListener{
		ch:       make(chan net.Conn),
		closedCh: make(chan any),
	}
}

func (ln *connListener) Accept() (net.Conn, error) {
	select {
	case <-ln.closedCh:
		// TODO(oxtoacart): make this error match what a regular net.Listener does
		return nil, syscall.EINVAL
	case conn := <-ln.ch:
		return conn, nil
	}
}

// Addr implements net.Listener. This always returns nil. It is assumed that
// this method is currently unused, so it logs a warning if it ever does get
// called.
func (ln *connListener) Addr() net.Addr {
	log.Println("warning: unexpected call to connListener.Addr()")
	return nil
}

func (ln *connListener) Close() error {
	ln.closeMu.Lock()
	defer ln.closeMu.Unlock()

	select {
	case <-ln.closedCh:
		// Already closed.
		return syscall.EINVAL
	default:
		// We don't close l.ch because someone maybe trying to send to that,
		// which would cause a panic.
		close(ln.closedCh)
		return nil
	}
}

func (ln *connListener) HandleConn(c net.Conn, remoteAddr net.Addr) error {
	select {
	case <-ln.closedCh:
		return syscall.EINVAL
	case ln.ch <- &connWithRemoteAddr{Conn: c, remoteAddr: remoteAddr}:
		// Connection has been accepted.
	}
	return nil
}

type connWithRemoteAddr struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connWithRemoteAddr) RemoteAddr() net.Addr {
	return c.remoteAddr
}
