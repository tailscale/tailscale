// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package memnet

import (
	"net"
	"net/netip"
	"time"
)

// NetworkName is the network name returned by [net.Addr.Network]
// for [net.Conn.LocalAddr] and [net.Conn.RemoteAddr] from the [Conn] type.
const NetworkName = "mem"

// Conn is a net.Conn that can additionally have its reads and writes blocked and unblocked.
type Conn interface {
	net.Conn

	// SetReadBlock blocks or unblocks the Read method of this Conn.
	// It reports an error if the existing value matches the new value,
	// or if the Conn has been Closed.
	SetReadBlock(bool) error

	// SetWriteBlock blocks or unblocks the Write method of this Conn.
	// It reports an error if the existing value matches the new value,
	// or if the Conn has been Closed.
	SetWriteBlock(bool) error
}

// NewConn creates a pair of Conns that are wired together by pipes.
func NewConn(name string, maxBuf int) (Conn, Conn) {
	r := NewPipe(name+"|0", maxBuf)
	w := NewPipe(name+"|1", maxBuf)

	return &connHalf{r: r, w: w}, &connHalf{r: w, w: r}
}

// NewTCPConn creates a pair of Conns that are wired together by pipes.
func NewTCPConn(src, dst netip.AddrPort, maxBuf int) (local Conn, remote Conn) {
	r := NewPipe(src.String(), maxBuf)
	w := NewPipe(dst.String(), maxBuf)

	lAddr := net.TCPAddrFromAddrPort(src)
	rAddr := net.TCPAddrFromAddrPort(dst)

	return &connHalf{r: r, w: w, remote: rAddr, local: lAddr}, &connHalf{r: w, w: r, remote: lAddr, local: rAddr}
}

type connAddr string

func (a connAddr) Network() string { return NetworkName }
func (a connAddr) String() string  { return string(a) }

type connHalf struct {
	local, remote net.Addr
	r, w          *Pipe
}

func (c *connHalf) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return connAddr(c.r.name)
}

func (c *connHalf) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return connAddr(c.w.name)
}

func (c *connHalf) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}
func (c *connHalf) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *connHalf) Close() error {
	if err := c.w.Close(); err != nil {
		return err
	}
	return c.r.Close()
}

func (c *connHalf) SetDeadline(t time.Time) error {
	err1 := c.SetReadDeadline(t)
	err2 := c.SetWriteDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}
func (c *connHalf) SetReadDeadline(t time.Time) error {
	return c.r.SetReadDeadline(t)
}
func (c *connHalf) SetWriteDeadline(t time.Time) error {
	return c.w.SetWriteDeadline(t)
}

func (c *connHalf) SetReadBlock(b bool) error {
	if b {
		return c.r.Block()
	}
	return c.r.Unblock()
}
func (c *connHalf) SetWriteBlock(b bool) error {
	if b {
		return c.w.Block()
	}
	return c.w.Unblock()
}
