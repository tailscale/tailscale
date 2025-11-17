// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/netstack/gro"
)

type queue struct {
	// TODO(jwhited): evaluate performance with a non-channel buffer.
	c chan *stack.PacketBuffer

	closeOnce sync.Once
	closedCh  chan struct{}

	mu     sync.RWMutex
	closed bool
}

func (q *queue) Close() {
	q.closeOnce.Do(func() {
		close(q.closedCh)
	})

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	close(q.c)
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
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return &tcpip.ErrClosedForSend{}
	}
	select {
	case q.c <- pkt.IncRef():
		return nil
	case <-q.closedCh:
		pkt.DecRef()
		return &tcpip.ErrClosedForSend{}
	}
}

func (q *queue) Drain() int {
	c := 0
	for pkt := range q.c {
		pkt.DecRef()
		c++
	}
	return c
}

func (q *queue) Num() int {
	return len(q.c)
}

var _ stack.LinkEndpoint = (*linkEndpoint)(nil)
var _ stack.GSOEndpoint = (*linkEndpoint)(nil)

type supportedGRO int

const (
	groNotSupported supportedGRO = iota
	tcpGROSupported
)

// linkEndpoint implements stack.LinkEndpoint and stack.GSOEndpoint. Outbound
// packets written by gVisor towards Tailscale are stored in a channel.
// Inbound is fed to gVisor via injectInbound or gro. This is loosely
// modeled after gvisor.dev/pkg/tcpip/link/channel.Endpoint.
type linkEndpoint struct {
	SupportedGSOKind stack.SupportedGSO
	supportedGRO     supportedGRO

	mu         sync.RWMutex // mu guards the following fields
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress
	mtu        uint32

	q *queue // outbound
}

func newLinkEndpoint(size int, mtu uint32, linkAddr tcpip.LinkAddress, supportedGRO supportedGRO) *linkEndpoint {
	le := &linkEndpoint{
		supportedGRO: supportedGRO,
		q: &queue{
			c:        make(chan *stack.PacketBuffer, size),
			closedCh: make(chan struct{}),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
	}
	return le
}

// gro attempts to enqueue p on g if ep supports a GRO kind matching the
// transport protocol carried in p. gro may allocate g if it is nil. gro can
// either return the existing g, a newly allocated one, or nil. Callers are
// responsible for calling Flush() on the returned value if it is non-nil once
// they have finished iterating through all GRO candidates for a given vector.
// If gro allocates a *gro.GRO it will have ep's stack.NetworkDispatcher set via
// SetDispatcher().
func (ep *linkEndpoint) gro(p *packet.Parsed, g *gro.GRO) *gro.GRO {
	if !buildfeatures.HasGRO || ep.supportedGRO == groNotSupported || p.IPProto != ipproto.TCP {
		// IPv6 may have extension headers preceding a TCP header, but we trade
		// for a fast path and assume p cannot be coalesced in such a case.
		ep.injectInbound(p)
		return g
	}
	if g == nil {
		ep.mu.RLock()
		d := ep.dispatcher
		ep.mu.RUnlock()
		g = gro.NewGRO()
		g.SetDispatcher(d)
	}
	g.Enqueue(p)
	return g
}

// Close closes l. Further packet injections will return an error, and all
// pending packets are discarded. Close may be called concurrently with
// WritePackets.
func (ep *linkEndpoint) Close() {
	ep.mu.Lock()
	ep.dispatcher = nil
	ep.mu.Unlock()
	ep.q.Close()
	ep.Drain()
}

// Read does non-blocking read one packet from the outbound packet queue.
func (ep *linkEndpoint) Read() *stack.PacketBuffer {
	return ep.q.Read()
}

// ReadContext does blocking read for one packet from the outbound packet queue.
// It can be cancelled by ctx, and in this case, it returns nil.
func (ep *linkEndpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	return ep.q.ReadContext(ctx)
}

// Drain removes all outbound packets from the channel and counts them.
func (ep *linkEndpoint) Drain() int {
	return ep.q.Drain()
}

// NumQueued returns the number of packets queued for outbound.
func (ep *linkEndpoint) NumQueued() int {
	return ep.q.Num()
}

func (ep *linkEndpoint) injectInbound(p *packet.Parsed) {
	ep.mu.RLock()
	d := ep.dispatcher
	ep.mu.RUnlock()
	if d == nil || !buildfeatures.HasNetstack {
		return
	}
	pkt := gro.RXChecksumOffload(p)
	if pkt == nil {
		return
	}
	d.DeliverNetworkPacket(pkt.NetworkProtocolNumber, pkt)
	pkt.DecRef()
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (ep *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (ep *linkEndpoint) IsAttached() bool {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (ep *linkEndpoint) MTU() uint32 {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (ep *linkEndpoint) SetMTU(mtu uint32) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.mtu = mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (ep *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	// We are required to offload RX checksum validation for the purposes of
	// GRO.
	return stack.CapabilityRXChecksumOffload
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*linkEndpoint) GSOMaxSize() uint32 {
	// This an increase from 32k returned by channel.Endpoint.GSOMaxSize() to
	// 64k, which improves throughput.
	return (1 << 16) - 1
}

// SupportedGSO implements stack.GSOEndpoint.
func (ep *linkEndpoint) SupportedGSO() stack.SupportedGSO {
	return ep.SupportedGSOKind
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*linkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (ep *linkEndpoint) LinkAddress() tcpip.LinkAddress {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (ep *linkEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.linkAddr = addr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (ep *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	// TODO(jwhited): evaluate writing a stack.PacketBufferList instead of a
	//  single packet. We can split 2 x 64K GSO across
	//  wireguard-go/conn.IdealBatchSize (128 slots) @ 1280 MTU, and non-GSO we
	//  could do more. Read API would need to change to take advantage. Verify
	//  gVisor limits around max number of segments packed together. Since we
	//  control MTU (and by effect TCP MSS in gVisor) we *shouldn't* expect to
	//  ever overflow 128 slots (see wireguard-go/tun.ErrTooManySegments usage).
	for _, pkt := range pkts.AsSlice() {
		if err := ep.q.Write(pkt); err != nil {
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
