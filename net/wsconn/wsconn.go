// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package wsconn contains an adapter type that turns
// a websocket connection into a net.Conn.
package wsconn

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// NetConn converts a *websocket.Conn into a net.Conn.
//
// It's for tunneling arbitrary protocols over WebSockets.
// Few users of the library will need this but it's tricky to implement
// correctly and so provided in the library.
// See https://github.com/nhooyr/websocket/issues/100.
//
// Every Write to the net.Conn will correspond to a message write of
// the given type on *websocket.Conn.
//
// The passed ctx bounds the lifetime of the net.Conn. If cancelled,
// all reads and writes on the net.Conn will be cancelled.
//
// If a message is read that is not of the correct type, the connection
// will be closed with StatusUnsupportedData and an error will be returned.
//
// Close will close the *websocket.Conn with StatusNormalClosure.
//
// When a deadline is hit, the connection will be closed. This is
// different from most net.Conn implementations where only the
// reading/writing goroutines are interrupted but the connection is kept alive.
//
// The Addr methods will return a mock net.Addr that returns "websocket" for Network
// and "websocket/unknown-addr" for String.
//
// A received StatusNormalClosure or StatusGoingAway close frame will be translated to
// io.EOF when reading.
//
// The given remoteAddr will be the value of the returned conn's
// RemoteAddr().String(). For best compatibility with consumers of
// conns, the string should be an ip:port if available, but in the
// absence of that it can be any string that describes the remote
// endpoint, or the empty string to makes RemoteAddr() return a place
// holder value.
func NetConn(ctx context.Context, c *websocket.Conn, msgType websocket.MessageType, remoteAddr string) net.Conn {
	nc := &netConn{
		c:          c,
		msgType:    msgType,
		remoteAddr: remoteAddr,
	}

	var writeCancel context.CancelFunc
	nc.writeContext, writeCancel = context.WithCancel(ctx)
	nc.writeTimer = time.AfterFunc(math.MaxInt64, func() {
		nc.afterWriteDeadline.Store(true)
		if nc.writing.Load() {
			writeCancel()
		}
	})
	if !nc.writeTimer.Stop() {
		<-nc.writeTimer.C
	}

	var readCancel context.CancelFunc
	nc.readContext, readCancel = context.WithCancel(ctx)
	nc.readTimer = time.AfterFunc(math.MaxInt64, func() {
		nc.afterReadDeadline.Store(true)
		if nc.reading.Load() {
			readCancel()
		}
	})
	if !nc.readTimer.Stop() {
		<-nc.readTimer.C
	}

	return nc
}

type netConn struct {
	c          *websocket.Conn
	msgType    websocket.MessageType
	remoteAddr string

	writeTimer         *time.Timer
	writeContext       context.Context
	writing            atomic.Bool
	afterWriteDeadline atomic.Bool

	readTimer         *time.Timer
	readContext       context.Context
	reading           atomic.Bool
	afterReadDeadline atomic.Bool

	readMu sync.Mutex
	// eofed is true if the reader should return io.EOF from the Read call.
	//
	// +checklocks:readMu
	eofed bool
	// +checklocks:readMu
	reader io.Reader
}

var _ net.Conn = &netConn{}

func (c *netConn) Close() error {
	return c.c.Close(websocket.StatusNormalClosure, "")
}

func (c *netConn) Write(p []byte) (int, error) {
	if c.afterWriteDeadline.Load() {
		return 0, os.ErrDeadlineExceeded
	}

	if swapped := c.writing.CompareAndSwap(false, true); !swapped {
		panic("Concurrent writes not allowed")
	}
	defer c.writing.Store(false)

	err := c.c.Write(c.writeContext, c.msgType, p)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *netConn) Read(p []byte) (int, error) {
	if c.afterReadDeadline.Load() {
		return 0, os.ErrDeadlineExceeded
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()
	if swapped := c.reading.CompareAndSwap(false, true); !swapped {
		panic("Concurrent reads not allowed")
	}
	defer c.reading.Store(false)

	if c.eofed {
		return 0, io.EOF
	}

	if c.reader == nil {
		typ, r, err := c.c.Reader(c.readContext)
		if err != nil {
			switch websocket.CloseStatus(err) {
			case websocket.StatusNormalClosure, websocket.StatusGoingAway:
				c.eofed = true
				return 0, io.EOF
			}
			return 0, err
		}
		if typ != c.msgType {
			err := fmt.Errorf("unexpected frame type read (expected %v): %v", c.msgType, typ)
			c.c.Close(websocket.StatusUnsupportedData, err.Error())
			return 0, err
		}
		c.reader = r
	}

	n, err := c.reader.Read(p)
	if err == io.EOF {
		c.reader = nil
		err = nil
	}
	return n, err
}

type websocketAddr struct {
	addr string
}

func (a websocketAddr) Network() string {
	return "websocket"
}

func (a websocketAddr) String() string {
	if a.addr != "" {
		return a.addr
	}
	return "websocket/unknown-addr"
}

func (c *netConn) RemoteAddr() net.Addr {
	return websocketAddr{c.remoteAddr}
}

func (c *netConn) LocalAddr() net.Addr {
	return websocketAddr{""}
}

func (c *netConn) SetDeadline(t time.Time) error {
	c.SetWriteDeadline(t)
	c.SetReadDeadline(t)
	return nil
}

func (c *netConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeTimer.Stop()
	} else {
		c.writeTimer.Reset(time.Until(t))
	}
	c.afterWriteDeadline.Store(false)
	return nil
}

func (c *netConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readTimer.Stop()
	} else {
		c.readTimer.Reset(time.Until(t))
	}
	c.afterReadDeadline.Store(false)
	return nil
}
