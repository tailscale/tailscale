// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netutil contains misc shared networking code & types.
package netutil

import (
	"io"
	"net"
)

// NewOneConnListener returns a net.Listener that returns c on its first
// Accept and EOF thereafter. The Listener's Addr is a dummy address.
func NewOneConnListener(c net.Conn) net.Listener {
	return NewOneConnListenerFrom(c, dummyListener{})
}

// NewOneConnListenerFrom returns a net.Listener wrapping ln where
// its Accept returns c on the first call and io.EOF thereafter.
func NewOneConnListenerFrom(c net.Conn, ln net.Listener) net.Listener {
	return &oneConnListener{c, ln}
}

type oneConnListener struct {
	conn net.Conn
	net.Listener
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

type dummyListener struct{}

func (dummyListener) Close() error                    { return nil }
func (dummyListener) Addr() net.Addr                  { return dummyAddr("unused-address") }
func (dummyListener) Accept() (c net.Conn, err error) { return nil, io.EOF }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
