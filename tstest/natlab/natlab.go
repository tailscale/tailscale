// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 in development
//lint:file-ignore S1000 in development

// Package natlab lets us simulate different types of networks all
// in-memory without running VMs or requiring root, etc. Despite the
// name, it does more than just NATs. But NATs are the most
// interesting.
package natlab

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"inet.af/netaddr"
)

// PacketConner is something that return a PacketConn.
//
// The different network types are all PacketConners.
type PacketConner interface {
	PacketConn() net.PacketConn
}

type Network struct {
	dhcpPool netaddr.IPPrefix
	alloced  map[netaddr.IP]bool

	pushRoute netaddr.IPPrefix
}

type iface struct {
	net *Network
	up  bool
	ips []netaddr.IP
}

type routeEntry struct {
	prefix netaddr.IPPrefix
	iface  *iface
}

// A Machine is a representation of an operating system's network stack.
// It has a network routing table and can have multiple attached networks.
type Machine struct {
	mu         sync.Mutex
	interfaces []*iface
	routes     []routeEntry // sorted by longest prefix to shortest

	conns map[netaddr.IPPort]*conn
}

func (m *Machine) hasv6() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.interfaces {
		for _, ip := range f.ips {
			if ip.Is6() {
				return true
			}
		}
	}
	return false
}

func (m *Machine) registerConn(c *conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.conns[c.ipp]; ok {
		return fmt.Errorf("duplicate conn listening on %v", c.ipp)
	}
	m.conns[c.ipp] = c
	return nil
}

func (m *Machine) unregisterConn(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns, c.ipp)
}

func (m *Machine) AddNetwork(n *Network) {}

func (m *Machine) ListenPacket(network, address string) (net.PacketConn, error) {
	// if udp4, udp6, etc... look at address IP vs unspec
	var fam uint8
	switch network {
	default:
		return nil, fmt.Errorf("unsupported network type %q", network)
	case "udp":
	case "udp4":
		fam = 4
	case "udp6":
		fam = 6
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" {
		if m.hasv6() {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	ip, err := netaddr.ParseIP(host)
	if err != nil {
		return nil, err
	}
	ipp := netaddr.IPPort{IP: ip, Port: uint16(port)}

	c := &conn{
		m:   m,
		fam: fam,
		ipp: ipp,
	}
	if err := m.registerConn(c); err != nil {
		return nil, err
	}
	return c, nil
}

// conn is our net.PacketConn implementation
type conn struct {
	m   *Machine
	fam uint8 // 0, 4, or 6
	ipp netaddr.IPPort

	mu           sync.Mutex
	closed       bool
	readDeadline time.Time
	activeReads  map[*activeRead]bool
}

type activeRead struct {
	cancel context.CancelFunc
}

// readDeadlineExceeded reports whether the read deadline is set and has already passed.
func (c *conn) readDeadlineExceeded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.readDeadline.IsZero() && c.readDeadline.Before(time.Now())
}

func (c *conn) registerActiveRead(ar *activeRead, active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeReads == nil {
		c.activeReads = make(map[*activeRead]bool)
	}
	if active {
		c.activeReads[ar] = true
	} else {
		delete(c.activeReads, ar)
	}
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.m.unregisterConn(c)
	c.breakActiveReadsLocked()
	return nil
}

func (c *conn) breakActiveReadsLocked() {
	for ar := range c.activeReads {
		ar.cancel()
	}
	c.activeReads = nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.ipp.UDPAddr()
}

func (c *conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ar := &activeRead{cancel: cancel}

	if c.readDeadlineExceeded() {
		return 0, nil, context.DeadlineExceeded
	}

	c.registerActiveRead(ar, true)
	defer c.registerActiveRead(ar, false)

	select {
	// TODO: select on getting data
	case <-ctx.Done():
		return 0, nil, context.DeadlineExceeded
	}
}

func (c *conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("TODO")
}

func (c *conn) SetDeadline(t time.Time) error {
	panic("SetWriteDeadline unsupported; TODO when needed")
}
func (c *conn) SetWriteDeadline(t time.Time) error {
	panic("SetWriteDeadline unsupported; TODO when needed")
}
func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if t.After(now) {
		panic("SetReadDeadline in the future not yet supported; TODO?")
	}

	if !t.IsZero() && t.Before(now) {
		c.breakActiveReadsLocked()
	}
	c.readDeadline = t

	return nil
}
