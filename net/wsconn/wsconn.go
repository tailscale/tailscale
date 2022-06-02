// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wsconn contains an adapter type that turns
// a websocket connection into a net.Conn.
package wsconn

import (
	"context"
	"net"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// New returns a net.Conn wrapper around c,
// using c to send and receive binary messages with
// chunks of bytes with no defined framing, effectively
// discarding all WebSocket-level message framing.
func New(c *websocket.Conn) net.Conn {
	return &websocketConn{c: c}
}

// websocketConn implements net.Conn around a *websocket.Conn,
// treating a websocket.Conn as a byte stream, ignoring the WebSocket
// frame/message boundaries.
type websocketConn struct {
	c *websocket.Conn

	// rextra are extra bytes owned by the reader.
	rextra []byte

	mu         sync.Mutex
	rdeadline  time.Time
	cancelRead context.CancelFunc
}

func (wc *websocketConn) LocalAddr() net.Addr  { return addr{} }
func (wc *websocketConn) RemoteAddr() net.Addr { return addr{} }

type addr struct{}

func (addr) Network() string { return "websocket" }
func (addr) String() string  { return "websocket" }

func (wc *websocketConn) Read(p []byte) (n int, err error) {
	// Drain any leftover from previously.
	n = copy(p, wc.rextra)
	if n > 0 {
		wc.rextra = wc.rextra[n:]
		return n, nil
	}

	var ctx context.Context
	var cancel context.CancelFunc

	wc.mu.Lock()
	if dl := wc.rdeadline; !dl.IsZero() {
		ctx, cancel = context.WithDeadline(context.Background(), wc.rdeadline)
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(30*24*time.Hour))
		wc.rdeadline = time.Time{}
	}
	wc.cancelRead = cancel
	wc.mu.Unlock()
	defer cancel()

	_, buf, err := wc.c.Read(ctx)
	n = copy(p, buf)
	wc.rextra = buf[n:]
	return n, err
}

func (wc *websocketConn) Write(p []byte) (n int, err error) {
	err = wc.c.Write(context.Background(), websocket.MessageBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (wc *websocketConn) Close() error { return wc.c.Close(websocket.StatusNormalClosure, "close") }

func (wc *websocketConn) SetDeadline(t time.Time) error {
	wc.SetReadDeadline(t)
	wc.SetWriteDeadline(t)
	return nil
}

func (wc *websocketConn) SetReadDeadline(t time.Time) error {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if !t.IsZero() && (wc.rdeadline.IsZero() || t.Before(wc.rdeadline)) && wc.cancelRead != nil {
		wc.cancelRead()
	}
	wc.rdeadline = t
	return nil
}

func (wc *websocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
