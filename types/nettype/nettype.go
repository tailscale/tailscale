// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nettype defines an interface that doesn't exist in the Go net package.
package nettype

import (
	"context"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PacketListener defines the ListenPacket method as implemented
// by net.ListenConfig, net.ListenPacket, and tstest/natlab.
type PacketListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type PacketListenerWithNetIP interface {
	ListenPacket(ctx context.Context, network, address string) (PacketConn, error)
}

// Std implements PacketListener using the Go net package's ListenPacket func.
type Std struct{}

func (Std) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var conf net.ListenConfig
	return conf.ListenPacket(ctx, network, address)
}

type PacketConn interface {
	net.PacketConn
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}

func MakePacketListenerWithNetIP(ln PacketListener) PacketListenerWithNetIP {
	return packetListenerAdapter{ln}
}

type packetListenerAdapter struct {
	PacketListener
}

type packetConnWithBatch struct {
	PacketConn
	xpc4 *ipv4.PacketConn
	xpc6 *ipv6.PacketConn
}

func (p packetConnWithBatch) WriteBatchIPv4(ms []ipv4.Message, flags int) (int, error) {
	return p.xpc4.WriteBatch(ms, flags)
}

func (p packetConnWithBatch) ReadBatchIPv4(ms []ipv4.Message, flags int) (int, error) {
	return p.xpc4.ReadBatch(ms, flags)
}

func (p packetConnWithBatch) WriteBatchIPv6(ms []ipv6.Message, flags int) (int, error) {
	return p.xpc6.WriteBatch(ms, flags)
}

func (p packetConnWithBatch) ReadBatchIPv6(ms []ipv6.Message, flags int) (int, error) {
	return p.xpc6.ReadBatch(ms, flags)
}

func (a packetListenerAdapter) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	pc, err := a.PacketListener.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return packetConnWithBatch{
		PacketConn: pc.(PacketConn),
		xpc4:       ipv4.NewPacketConn(pc),
		xpc6:       ipv6.NewPacketConn(pc),
	}, nil
}

type BatchWriter interface {
	WriteBatchIPv4([]ipv4.Message, int) (int, error)
	WriteBatchIPv6([]ipv6.Message, int) (int, error)
}

type BatchReader interface {
	ReadBatchIPv4([]ipv4.Message, int) (int, error)
	ReadBatchIPv6([]ipv6.Message, int) (int, error)
}
