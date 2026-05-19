// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"net"
	"time"
)

// conn is the [net.Conn] implementation returned by [Server.Dial] and by
// the listener's Accept once the datapath channel is wired up.
//
// All methods currently panic. The implementation will be filled in by a
// later agent; the type exists today so the package compiles and so
// callers can perform interface type assertions.
type conn struct {
	s      *Server
	local  addr
	remote addr
}

// Compile-time check that *conn satisfies net.Conn.
var _ net.Conn = (*conn)(nil)

func (c *conn) Read(b []byte) (int, error) {
	panic("tsnet2: conn.Read not implemented")
}

func (c *conn) Write(b []byte) (int, error) {
	panic("tsnet2: conn.Write not implemented")
}

func (c *conn) Close() error {
	panic("tsnet2: conn.Close not implemented")
}

func (c *conn) LocalAddr() net.Addr  { return c.local }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

func (c *conn) SetDeadline(t time.Time) error {
	panic("tsnet2: conn.SetDeadline not implemented")
}

func (c *conn) SetReadDeadline(t time.Time) error {
	panic("tsnet2: conn.SetReadDeadline not implemented")
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	panic("tsnet2: conn.SetWriteDeadline not implemented")
}
