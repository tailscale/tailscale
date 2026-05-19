// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package clientsock contains helpers for dialing the tsnet2d Unix
// socket and performing the small handshake that selects a channel
// kind.
package clientsock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"tailscale.com/tsnet2/proto"
)

// Dial connects to the daemon Unix socket at path and writes a single
// byte selecting the channel kind. Callers can then use the returned
// net.Conn for channel-specific framing.
func Dial(ctx context.Context, path string, kind proto.ChannelKind) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{byte(kind)}); err != nil {
		c.Close()
		return nil, fmt.Errorf("clientsock: writing handshake: %w", err)
	}
	return c, nil
}

// RPCClient is a long-lived JSON-RPC client over a single control-channel
// connection. It dispatches responses by ID to per-call channels.
type RPCClient struct {
	conn net.Conn
	w    *proto.FrameWriter

	nextID atomic.Uint64

	mu       sync.Mutex
	pending  map[uint64]chan *proto.Frame
	closed   bool
	closeErr error
}

// NewRPCClient takes ownership of conn (must already be in control-channel
// mode after the handshake byte) and starts a reader goroutine that
// dispatches responses.
func NewRPCClient(conn net.Conn) *RPCClient {
	c := &RPCClient{
		conn:    conn,
		w:       proto.NewFrameWriter(conn),
		pending: make(map[uint64]chan *proto.Frame),
	}
	go c.readLoop()
	return c
}

func (c *RPCClient) readLoop() {
	fr := proto.NewFrameReader(c.conn)
	var loopErr error
	for {
		f, err := fr.Next()
		if err != nil {
			loopErr = err
			break
		}
		if f.ID == 0 {
			// We don't (yet) use server-initiated notifications.
			continue
		}
		c.mu.Lock()
		ch, ok := c.pending[f.ID]
		delete(c.pending, f.ID)
		c.mu.Unlock()
		if ok {
			ch <- f
		}
	}
	c.mu.Lock()
	c.closed = true
	c.closeErr = loopErr
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, ch := range pending {
		ch <- &proto.Frame{Error: fmt.Sprintf("tsnet2: control channel closed: %v", loopErr)}
	}
}

// Call issues a single RPC and decodes the result into resOut. It returns
// the wire-level error if the server returned one.
func (c *RPCClient) Call(ctx context.Context, method string, params, resOut any) error {
	id := c.nextID.Add(1)
	var paramsBytes []byte
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("tsnet2 rpc: marshal params: %w", err)
		}
		paramsBytes = b
	}
	ch := make(chan *proto.Frame, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("tsnet2 rpc: control channel closed: %v", c.closeErr)
	}
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.w.Write(&proto.Frame{ID: id, Method: method, Params: paramsBytes}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("tsnet2 rpc: write: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp := <-ch:
		if resp.Error != "" {
			return fmt.Errorf("%s", resp.Error)
		}
		if resOut != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, resOut); err != nil {
				return fmt.Errorf("tsnet2 rpc: unmarshal result: %w", err)
			}
		}
		return nil
	}
}

// Close closes the underlying connection and aborts any pending calls.
func (c *RPCClient) Close() error {
	return c.conn.Close()
}

// CopyTo is a small helper that wraps io.Copy with sensible defaults.
// It is currently unused but kept for forthcoming streaming endpoints.
func CopyTo(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
