// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"context"
	"net"

	"tailscale.com/types/nettype"
)

var listenPacket = listenPacketStd

var _ nettype.PacketListenerWithNetIP = (*PacketListener)(nil)

// PacketListener is a [nettype.PacketListenerWithNetIP] implementation that
// creates packet connections optimized for high throughput on platforms that
// support batched I/O.
type PacketListener struct {
	config    *net.ListenConfig
	batchSize int
}

// NewPacketListener returns a new [PacketListener] that uses the provided
// [net.ListenConfig] to configure new connections, and attempts to enable
// batched I/O with the provided batchSize if supported on the current platform.
func NewPacketListener(config *net.ListenConfig, batchSize int) nettype.PacketListenerWithNetIP {
	return &PacketListener{config, batchSize}
}

// ListenPacket implements [nettype.PacketListenerWithNetIP].
// On platforms that support batched I/O, the returned [nettype.PacketConn]
// is a [Conn].
func (pl *PacketListener) ListenPacket(ctx context.Context, network, address string) (nettype.PacketConn, error) {
	return listenPacket(ctx, network, address, pl.config, pl.batchSize)
}

var _ nettype.PacketConn = (*net.UDPConn)(nil)

// listenPacketStd creates a [net.UDPConn] and attempts to upgrade it to
// a [Conn] if supported on the current platform (as of 2026-01-22, only Linux).
func listenPacketStd(ctx context.Context, network, address string, config *net.ListenConfig, batchSize int) (nettype.PacketConn, error) {
	conn, err := config.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return tryUpgradeToConn(conn.(nettype.PacketConn), network, batchSize), nil
}
