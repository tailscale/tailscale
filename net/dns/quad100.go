// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type Quad100conn struct {
	Ctx        context.Context
	DnsManager *Manager

	rbuf bytes.Buffer
}

var (
	_ net.Conn       = (*Quad100conn)(nil)
	_ net.PacketConn = (*Quad100conn)(nil) // be a PacketConn to change net.Resolver semantics
)

func (*Quad100conn) Close() error                       { return nil }
func (*Quad100conn) LocalAddr() net.Addr                { return todoAddr{} }
func (*Quad100conn) RemoteAddr() net.Addr               { return todoAddr{} }
func (*Quad100conn) SetDeadline(t time.Time) error      { return nil }
func (*Quad100conn) SetReadDeadline(t time.Time) error  { return nil }
func (*Quad100conn) SetWriteDeadline(t time.Time) error { return nil }

func (c *Quad100conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *Quad100conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, todoAddr{}, err
}

func (c *Quad100conn) Read(p []byte) (n int, err error) {
	return c.rbuf.Read(p)
}

func (c *Quad100conn) Write(packet []byte) (n int, err error) {
	pkt, err := c.DnsManager.Query(c.Ctx, packet, "tcp", netip.AddrPort{})
	if err != nil {
		return 0, err
	}
	c.rbuf.Write(pkt)
	return len(packet), nil
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }

func Quad100Resolver(ctx context.Context, mgr *Manager) func(host string) (netip.Addr, error) {
	return func(host string) (netip.Addr, error) {
		var r net.Resolver
		r.PreferGo = true
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return &Quad100conn{
				Ctx:        ctx,
				DnsManager: mgr,
			}, nil
		}

		ips, err := r.LookupIP(ctx, "ip4", host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(ips) == 0 {
			return netip.Addr{}, fmt.Errorf("DNS lookup returned no results for %q", host)
		}
		ip, _ := netip.AddrFromSlice(ips[0])
		return ip, nil
	}
}
