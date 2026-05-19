// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"bufio"
	"net"
	"time"
)

// conn wraps a daemon datapath/accept connection and exposes it as a
// net.Conn to the application. Reads pull from any buffered bytes left
// over from header parsing first, then fall through to the underlying
// connection.
type conn struct {
	s      *Server
	nc     net.Conn
	reader *bufio.Reader // optional; used to drain any pre-buffered bytes

	local  addr
	remote addr
}

var _ net.Conn = (*conn)(nil)

func (c *conn) Read(b []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		return c.reader.Read(b)
	}
	return c.nc.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	return c.nc.Write(b)
}

func (c *conn) Close() error {
	return c.nc.Close()
}

func (c *conn) LocalAddr() net.Addr  { return c.local }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

func (c *conn) SetDeadline(t time.Time) error      { return c.nc.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.nc.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }
