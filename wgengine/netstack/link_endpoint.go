// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type queue struct {
	// TODO(jwhited): evaluate performance with mu as Mutex and/or alternative
	//  non-channel buffer.
	c      chan *stack.PacketBuffer
	mu     sync.RWMutex // mu guards closed
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
	defer q.mu.RUnlock()
	if q.closed {
		return &tcpip.ErrClosedForSend{}
	}

	wrote := false
	select {
	case q.c <- pkt.IncRef():
		wrote = true
	default:
		// TODO(jwhited): reconsider/count
		pkt.DecRef()
	}

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

// linkEndpoint implements stack.LinkEndpoint and stack.GSOEndpoint. Outbound
// packets written by gVisor towards Tailscale are stored in a channel.
// Inbound is fed to gVisor via InjectInbound. This is loosely modeled after
// gvisor.dev/pkg/tcpip/link/channel.Endpoint.
type linkEndpoint struct {
	LinkEPCapabilities stack.LinkEndpointCapabilities
	SupportedGSOKind   stack.SupportedGSO

	mu         sync.RWMutex // mu guards the following fields
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress
	mtu        uint32

	q *queue // outbound
}

func newLinkEndpoint(size int, mtu uint32, linkAddr tcpip.LinkAddress) *linkEndpoint {
	return &linkEndpoint{
		q: &queue{
			c: make(chan *stack.PacketBuffer, size),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}

// Close closes l. Further packet injections will return an error, and all
// pending packets are discarded. Close may be called concurrently with
// WritePackets.
func (l *linkEndpoint) Close() {
	l.q.Close()
	l.Drain()
}

// Read does non-blocking read one packet from the outbound packet queue.
func (l *linkEndpoint) Read() *stack.PacketBuffer {
	return l.q.Read()
}

// ReadContext does blocking read for one packet from the outbound packet queue.
// It can be cancelled by ctx, and in this case, it returns nil.
func (l *linkEndpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	return l.q.ReadContext(ctx)
}

// Drain removes all outbound packets from the channel and counts them.
func (l *linkEndpoint) Drain() int {
	c := 0
	for pkt := l.Read(); pkt != nil; pkt = l.Read() {
		pkt.DecRef()
		c++
	}
	return c
}

// NumQueued returns the number of packet queued for outbound.
func (l *linkEndpoint) NumQueued() int {
	return l.q.Num()
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
func (l *linkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	l.mu.RLock()
	d := l.dispatcher
	l.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (l *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (l *linkEndpoint) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (l *linkEndpoint) MTU() uint32 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (l *linkEndpoint) SetMTU(mtu uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mtu = mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (l *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return l.LinkEPCapabilities
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*linkEndpoint) GSOMaxSize() uint32 {
	// This an increase from 32k returned by channel.Endpoint.GSOMaxSize() to
	// 64k, which improves throughput.
	return (1 << 16) - 1
}

// SupportedGSO implements stack.GSOEndpoint.
func (l *linkEndpoint) SupportedGSO() stack.SupportedGSO {
	return l.SupportedGSOKind
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*linkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (l *linkEndpoint) LinkAddress() tcpip.LinkAddress {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (l *linkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.linkAddr = addr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (l *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	// TODO(jwhited): evaluate writing a stack.PacketBufferList instead of a
	//  single packet. We can split 2 x 64K GSO across
	//  wireguard-go/conn.IdealBatchSize (128 slots) @ 1280 MTU, and non-GSO we
	//  could do more. Read API would need to change to take advantage. Verify
	//  gVisor limits around max number of segments packed together. Since we
	//  control MTU (and by effect TCP MSS in gVisor) we *shouldn't* expect to
	//  ever overflow 128 slots (see wireguard-go/tun.ErrTooManySegments usage).
	for _, pkt := range pkts.AsSlice() {
		if err := l.q.Write(pkt); err != nil {
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
