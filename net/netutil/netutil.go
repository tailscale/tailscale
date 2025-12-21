// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netutil contains misc shared networking code & types.
package netutil

import (
	"bufio"
	"io"
	"net"

	"tailscale.com/syncs"
)

// NewOneConnListener returns a net.Listener that returns c on its
// first Accept and EOF thereafter.
//
// The returned Listener's Addr method returns addr if non-nil. If nil,
// Addr returns a non-nil dummy address instead.
func NewOneConnListener(c net.Conn, addr net.Addr) net.Listener {
	if addr == nil {
		addr = dummyAddr("one-conn-listener")
	}
	return &oneConnListener{
		addr: addr,
		conn: c,
	}
}

type oneConnListener struct {
	addr net.Addr

	mu   syncs.Mutex
	conn net.Conn
}

func (ln *oneConnListener) Accept() (c net.Conn, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	c = ln.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	ln.conn = nil
	return
}

func (ln *oneConnListener) Addr() net.Addr { return ln.addr }

func (ln *oneConnListener) Close() error {
	ln.Accept() // guarantee future call returns io.EOF
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// NewDrainBufConn returns a net.Conn conditionally wrapping c,
// prefixing any bytes that are in initialReadBuf, which may be nil.
func NewDrainBufConn(c net.Conn, initialReadBuf *bufio.Reader) net.Conn {
	r := initialReadBuf
	if r != nil && r.Buffered() == 0 {
		r = nil
	}
	return &drainBufConn{c, r}
}

// drainBufConn is a net.Conn with an initial bunch of bytes in a
// bufio.Reader. Read drains the bufio.Reader until empty, then passes
// through subsequent reads to the Conn directly.
type drainBufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *drainBufConn) Read(bs []byte) (int, error) {
	if b.r == nil {
		return b.Conn.Read(bs)
	}
	n, err := b.r.Read(bs)
	if b.r.Buffered() == 0 {
		b.r = nil
	}
	return n, err
}

// NewAltReadWriteCloserConn returns a net.Conn that wraps rwc (for
// Read, Write, and Close) and c (for all other methods).
func NewAltReadWriteCloserConn(rwc io.ReadWriteCloser, c net.Conn) net.Conn {
	return wrappedConn{c, rwc}
}

type wrappedConn struct {
	net.Conn
	rwc io.ReadWriteCloser
}

func (w wrappedConn) Read(bs []byte) (int, error) {
	return w.rwc.Read(bs)
}

func (w wrappedConn) Write(bs []byte) (int, error) {
	return w.rwc.Write(bs)
}

func (w wrappedConn) Close() error {
	return w.rwc.Close()
}
