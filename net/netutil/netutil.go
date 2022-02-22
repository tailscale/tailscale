// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netutil contains misc shared networking code & types.
package netutil

import (
	"io"
	"net"
	"sync"
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

	mu   sync.Mutex
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

type dummyListener struct{}

func (dummyListener) Close() error                    { return nil }
func (dummyListener) Addr() net.Addr                  { return dummyAddr("unused-address") }
func (dummyListener) Accept() (c net.Conn, err error) { return nil, io.EOF }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
