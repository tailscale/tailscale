// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"context"
	"net"

	"tailscale.com/types/nettype"
)

// NewPacketListener returns a packet listener that uses Registered Input/Output (RIO)
// API Extensions, if available, to provide high-performance UDP networking on Windows.
// The specified options are applied to all connections created by the listener.
// If RIO is not available, it returns an [ErrRIOUnavailable].
func NewPacketListener(options ...UDPOption) (nettype.PacketListener, error) {
	if err := Initialize(); err != nil {
		return nil, err
	}
	return &PacketListener{options: options}, nil
}

// PacketListener is a [nettype.PacketListener] that uses RIO.
type PacketListener struct {
	options []UDPOption
}

// ListenPacket implements [nettype.PacketListener.ListenPacket].
func (pl *PacketListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Err: err}
	}
	return ListenUDP(network, addr, pl.options...)
}
