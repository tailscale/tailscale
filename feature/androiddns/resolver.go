// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package androiddns

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// NewResolver returns a net.Resolver that resolves names via the
// system resolver daemon instead of Go's usual name resolution paths.
func NewResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial:     resolverDial,
	}
}

// resolverDial is a net.Resolver.Dial hook. It ignores the network
// and address that Go's resolver chose (with no resolv.conf, those
// are the useless localhost defaults) and returns a conn that
// forwards each DNS query over dnsproxyd instead.
//
// Because the returned conn is not a net.PacketConn, Go's resolver
// applies TCP framing: each message is preceded by a two byte
// big-endian length.
func resolverDial(ctx context.Context, network, address string) (net.Conn, error) {
	return &streamConn{}, nil
}

// streamConn is a net.Conn that speaks TCP-style framed DNS on one
// side and dnsproxyd on the other. Go's resolver writes one framed
// query and then reads one framed answer; the daemon round trip
// happens on the first Read after a complete query has been written.
type streamConn struct {
	mu       sync.Mutex
	deadline time.Time
	wbuf     []byte // accumulated framed query bytes
	rbuf     []byte // framed answer bytes not yet read
	closed   bool
}

var (
	errClosed         = errors.New("androiddns: use of closed conn")
	errNoPendingQuery = errors.New("androiddns: read with no complete query written")
)

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	c.wbuf = append(c.wbuf, p...)
	return len(p), nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	if len(c.rbuf) == 0 {
		if err := c.roundTripLocked(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *streamConn) roundTripLocked() error {
	if len(c.wbuf) < 2 {
		return errNoPendingQuery
	}
	msgLen := int(c.wbuf[0])<<8 | int(c.wbuf[1])
	if len(c.wbuf) < 2+msgLen {
		return errNoPendingQuery
	}
	msg := c.wbuf[2 : 2+msgLen]

	ctx := context.Background()
	var cancel context.CancelFunc
	if !c.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}
	ans, err := Query(ctx, msg)
	if err != nil {
		return err
	}
	c.wbuf = c.wbuf[2+msgLen:]
	c.rbuf = append([]byte{byte(len(ans) >> 8), byte(len(ans))}, ans...)
	return nil
}

func (c *streamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *streamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *streamConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (c *streamConn) RemoteAddr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "dnsproxyd" }
func (fakeAddr) String() string  { return "dnsproxyd" }

// resolvConfExists reports whether the platform has an /etc/resolv.conf
// that Go's resolver could use.
func resolvConfExists() bool {
	fi, err := os.Stat("/etc/resolv.conf")
	return err == nil && fi.Size() > 0
}
