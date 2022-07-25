// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nettype defines an interface that doesn't exist in the Go net package.
package nettype

import (
	"context"
	"net"
	"net/netip"
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

func (a packetListenerAdapter) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	pc, err := a.PacketListener.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return pc.(PacketConn), nil
}
