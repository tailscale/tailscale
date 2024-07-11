// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netstack

import (
	"context"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

type queue struct {
	// c is the outbound packet channel.
	c  chan *stack.PacketBuffer
	mu sync.RWMutex
	// +checklocks:mu
	closed bool
}

func (q *queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		close(q.c)
	}
	q.closed = true
}

func (q *queue) Read() *stack.PacketBuffer {
	select {
	case p := <-q.c:
		return p
	default:
		return nil
	}
}

func (q *queue) ReadContext(ctx context.Context) *stack.PacketBuffer {
	select {
	case pkt := <-q.c:
		return pkt
	case <-ctx.Done():
		return nil
	}
}

func (q *queue) Write(pkt *stack.PacketBuffer) tcpip.Error {
	// q holds the PacketBuffer.
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return &tcpip.ErrClosedForSend{}
	}

	wrote := false
	select {
	case q.c <- pkt.IncRef():
		wrote = true
	default:
		pkt.DecRef()
	}
	q.mu.RUnlock()

	if wrote {
		return nil
	}
	return &tcpip.ErrNoBufferSpace{}
}

func (q *queue) Num() int {
	return len(q.c)
}

var _ stack.LinkEndpoint = (*linkEndpoint)(nil)
var _ stack.GSOEndpoint = (*linkEndpoint)(nil)

// linkEndpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
//
// +stateify savable
type linkEndpoint struct {
	LinkEPCapabilities stack.LinkEndpointCapabilities
	SupportedGSOKind   stack.SupportedGSO

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher
	// +checklocks:mu
	linkAddr tcpip.LinkAddress
	// +checklocks:mu
	mtu uint32

	// Outbound packet queue.
	q *queue

	gro *gro.GRO
}

// newLinkEndpoint creates a new channel endpoint.
func newLinkEndpoint(size int, mtu uint32, linkAddr tcpip.LinkAddress) *linkEndpoint {
	ep := &linkEndpoint{
		q: &queue{
			c: make(chan *stack.PacketBuffer, size),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
		gro:      &gro.GRO{},
	}
	ep.gro.Init(true)
	return ep
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *linkEndpoint) Close() {
	e.q.Close()
	e.Drain()
}

// Read does non-blocking read one packet from the outbound packet queue.
func (e *linkEndpoint) Read() *stack.PacketBuffer {
	return e.q.Read()
}

// ReadContext does blocking read for one packet from the outbound packet queue.
// It can be cancelled by ctx, and in this case, it returns nil.
func (e *linkEndpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	return e.q.ReadContext(ctx)
}

// Drain removes all outbound packets from the channel and counts them.
func (e *linkEndpoint) Drain() int {
	c := 0
	for pkt := e.Read(); pkt != nil; pkt = e.Read() {
		pkt.DecRef()
		c++
	}
	return c
}

// NumQueued returns the number of packet queued for outbound.
func (e *linkEndpoint) NumQueued() int {
	return e.q.Num()
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
func (e *linkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (e *linkEndpoint) GROEnqueue(pkt *stack.PacketBuffer) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.gro.Dispatcher == nil {
		pkt.DecRef()
		return
	}
	e.gro.Enqueue(pkt)
}

func (e *linkEndpoint) GROFlush() {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.gro.Dispatcher == nil {
		return
	}
	e.gro.Flush()
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
	e.gro.Dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *linkEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (e *linkEndpoint) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (e *linkEndpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEPCapabilities
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*linkEndpoint) GSOMaxSize() uint32 {
	return 1<<16 - 1
}

// SupportedGSO implements stack.GSOEndpoint.
func (e *linkEndpoint) SupportedGSO() stack.SupportedGSO {
	return e.SupportedGSOKind
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*linkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *linkEndpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (e *linkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if err := e.q.Write(pkt); err != nil {
			if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok && n == 0 {
				return 0, err
			}
			break
		}
		n++
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*linkEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*linkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*linkEndpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*linkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// SetOnCloseAction implements stack.LinkEndpoint.
func (*linkEndpoint) SetOnCloseAction(func()) {}
