// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gro

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
)

type GRO struct{}

func NewGRO() *GRO {
	panic("unsupported; removed")
}

func (g *GRO) SetDispatcher(_ stack.NetworkDispatcher) {}

func (g *GRO) Enqueue(_ *packet.Parsed) {}

func (g *GRO) Flush() {}
