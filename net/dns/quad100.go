// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"time"
)

// managerConn is a net.PacketConn suitable for returning from
// net.Dialer.Dial to send DNS queries to the Manager's DNS resolver.
type managerConn struct {
	ctx context.Context
	mgr *Manager

	rbuf bytes.Buffer
}

var (
	_ net.Conn       = (*managerConn)(nil)
	_ net.PacketConn = (*managerConn)(nil) // be a PacketConn to change net.Resolver semantics
)

func (*managerConn) Close() error                       { return nil }
func (*managerConn) LocalAddr() net.Addr                { return todoAddr{} }
func (*managerConn) RemoteAddr() net.Addr               { return todoAddr{} }
func (*managerConn) SetDeadline(t time.Time) error      { return nil }
func (*managerConn) SetReadDeadline(t time.Time) error  { return nil }
func (*managerConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *managerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *managerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, todoAddr{}, err
}

func (c *managerConn) Read(p []byte) (n int, err error) {
	return c.rbuf.Read(p)
}

func (c *managerConn) Write(packet []byte) (n int, err error) {
	pkt, err := c.mgr.Query(c.ctx, packet, "udp", netip.AddrPort{})
	if err != nil {
		return 0, err
	}
	if _, err := c.rbuf.Write(pkt); err != nil {
		return 0, err
	}
	return len(packet), nil
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }

// Quad100ResolverDial returns a net.Dialer.Dial function that dials
// the Manager's DNS resolver. This overrides the IP resolution,
// allowing the caller to get DNS responses from the Manager itself.
func Quad100ResolverDial(mgr *Manager) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return &managerConn{
			ctx: ctx,
			mgr: mgr,
		}, nil
	}
}
