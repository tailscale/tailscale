// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// gro on iOS delivers packets to its Dispatcher, immediately. This type exists
// to prevent importation of the gVisor GRO implementation as said package
// increases binary size. This is a penalty we do not wish to pay since we
// currently do not leverage GRO on iOS.
type gro struct {
	Dispatcher stack.NetworkDispatcher
}

func (g *gro) Init(v bool) {
	if v {
		panic("GRO is not supported on this platform")
	}
}

func (g *gro) Flush() {}

func (g *gro) Enqueue(pkt *stack.PacketBuffer) {
	g.Dispatcher.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
}
