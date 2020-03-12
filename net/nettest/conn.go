// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nettest

import (
	"io"
	"time"
)

// Conn is a bi-directional in-memory stream that looks like a TCP net.Conn.
type Conn interface {
	io.Reader
	io.Writer
	io.Closer

	// The *Deadline methods follow the semantics of net.Conn.

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error

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

type connHalf struct {
	r, w *Pipe
}

func (c *connHalf) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}
func (c *connHalf) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}
func (c *connHalf) Close() error {
	err1 := c.r.Close()
	err2 := c.w.Close()
	if err1 != nil {
		return err1
	}
	return err2
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
