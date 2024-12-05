// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nettype defines an interface that doesn't exist in the Go net package.
package nettype

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"
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

// PacketConn is like a net.PacketConn but uses the newer netip.AddrPort
// write/read methods.
type PacketConn interface {
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	io.Closer
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
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

// ConnPacketConn is the interface that's a superset of net.Conn and net.PacketConn.
type ConnPacketConn interface {
	net.Conn
	net.PacketConn
}
