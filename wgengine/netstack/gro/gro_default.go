// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_gro

package gro

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	nsgro "gvisor.dev/gvisor/pkg/tcpip/stack/gro"
	"tailscale.com/net/packet"
)

var (
	groPool sync.Pool
)

func init() {
	groPool.New = func() any {
		g := &GRO{}
		g.gro.Init(true)
		return g
	}
}

// GRO coalesces incoming packets to increase throughput. It is NOT thread-safe.
type GRO struct {
	gro           nsgro.GRO
	maybeEnqueued bool
}

// NewGRO returns a new instance of *GRO from a sync.Pool. It can be returned to
// the pool with GRO.Flush().
func NewGRO() *GRO {
	return groPool.Get().(*GRO)
}

// SetDispatcher sets the underlying stack.NetworkDispatcher where packets are
// delivered.
func (g *GRO) SetDispatcher(d stack.NetworkDispatcher) {
	g.gro.Dispatcher = d
}

// Enqueue enqueues the provided packet for GRO. It may immediately deliver
// it to the underlying stack.NetworkDispatcher depending on its contents. To
// explicitly flush previously enqueued packets see Flush().
func (g *GRO) Enqueue(p *packet.Parsed) {
	if g.gro.Dispatcher == nil {
		return
	}
	pkt := RXChecksumOffload(p)
	if pkt == nil {
		return
	}
	// TODO(jwhited): g.gro.Enqueue() duplicates a lot of p.Decode().
	//  We may want to push stack.PacketBuffer further up as a
	//  replacement for packet.Parsed, or inversely push packet.Parsed
	//  down into refactored GRO logic.
	g.gro.Enqueue(pkt)
	g.maybeEnqueued = true
	pkt.DecRef()
}

// Flush flushes previously enqueued packets to the underlying
// stack.NetworkDispatcher, and returns GRO to a pool for later re-use. Callers
// MUST NOT use GRO once it has been Flush()'d.
func (g *GRO) Flush() {
	if g.gro.Dispatcher != nil && g.maybeEnqueued {
		g.gro.Flush()
	}
	g.gro.Dispatcher = nil
	g.maybeEnqueued = false
	groPool.Put(g)
}
