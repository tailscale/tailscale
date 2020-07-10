// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nettype defines an interface that doesn't exist in the Go net package.
package nettype

import (
	"context"
	"net"
)

// PacketListener defines the ListenPacket method as implemented
// by net.ListenConfig, net.ListenPacket, and tstest/natlab.
type PacketListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

// Std implements PacketListener using the Go net package's ListenPacket func.
type Std struct{}

func (Std) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var conf net.ListenConfig
	return conf.ListenPacket(ctx, network, address)
}
