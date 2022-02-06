// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package packet provides the implementation of packet sockets (see
// packet(7)). Packet sockets allow applications to:
//
//   * manually write and inspect link, network, and transport headers
//   * receive all traffic of a given network protocol, or all protocols
//
// Packet sockets are similar to raw sockets, but provide even more power to
// users, letting them effectively talk directly to the network device.
//
// Packet sockets skip the input and output iptables chains.
package packet

import (
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type packet struct {
	packetEntry
	// data holds the actual packet data, including any headers and
	// payload.
	data       buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	receivedAt time.Time             `state:".(int64)"`
	// senderAddr is the network address of the sender.
	senderAddr tcpip.FullAddress
	// packetInfo holds additional information like the protocol
	// of the packet etc.
	packetInfo tcpip.LinkPacketInfo
}

// endpoint is the packet socket implementation of tcpip.Endpoint. It is legal
// to have goroutines make concurrent calls into the endpoint.
//
// Lock order:
//   endpoint.mu
//     endpoint.rcvMu
//
// +stateify savable
type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	cooked      bool
	ops         tcpip.SocketOptions
	stats       tcpip.TransportEndpointStats

	// The following fields are used to manage the receive queue.
	rcvMu sync.Mutex `state:"nosave"`
	// +checklocks:rcvMu
	rcvList packetList
	// +checklocks:rcvMu
	rcvBufSize int
	// +checklocks:rcvMu
	rcvClosed bool
	// +checklocks:rcvMu
	rcvDisabled bool

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	closed bool
	// +checklocks:mu
	boundNetProto tcpip.NetworkProtocolNumber
	// +checklocks:mu
	boundNIC tcpip.NICID

	lastErrorMu sync.Mutex `state:"nosave"`
	// +checklocks:lastErrorMu
	lastError tcpip.Error
}

// NewEndpoint returns a new packet endpoint.
func NewEndpoint(s *stack.Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	ep := &endpoint{
		stack:         s,
		cooked:        cooked,
		boundNetProto: netProto,
		waiterQueue:   waiterQueue,
	}
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	ep.ops.SetReceiveBufferSize(32*1024, false /* notify */)

	// Override with stack defaults.
	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		ep.ops.SetReceiveBufferSize(int64(rs.Default), false /* notify */)
	}

	if err := s.RegisterPacketEndpoint(0, netProto, ep); err != nil {
		return nil, err
	}
	return ep, nil
}

// Abort implements stack.TransportEndpoint.Abort.
func (ep *endpoint) Abort() {
	ep.Close()
}

// Close implements tcpip.Endpoint.Close.
func (ep *endpoint) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.closed {
		return
	}

	ep.stack.UnregisterPacketEndpoint(ep.boundNIC, ep.boundNetProto, ep)

	ep.rcvMu.Lock()
	defer ep.rcvMu.Unlock()

	// Clear the receive list.
	ep.rcvClosed = true
	ep.rcvBufSize = 0
	for !ep.rcvList.Empty() {
		ep.rcvList.Remove(ep.rcvList.Front())
	}

	ep.closed = true
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (*endpoint) ModerateRecvBuf(int) {}

// Read implements tcpip.Endpoint.Read.
func (ep *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	ep.rcvMu.Lock()

	// If there's no data to read, return that read would block or that the
	// endpoint is closed.
	if ep.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if ep.rcvClosed {
			ep.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		ep.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	packet := ep.rcvList.Front()
	if !opts.Peek {
		ep.rcvList.Remove(packet)
		ep.rcvBufSize -= packet.data.Size()
	}

	ep.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: packet.data.Size(),
		ControlMessages: tcpip.ControlMessages{
			HasTimestamp: true,
			Timestamp:    packet.receivedAt,
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = packet.senderAddr
	}
	if opts.NeedLinkPacketInfo {
		res.LinkPacketInfo = packet.packetInfo
	}

	n, err := packet.data.ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

func (ep *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	if !ep.stack.PacketEndpointWriteSupported() {
		return 0, &tcpip.ErrNotSupported{}
	}

	ep.mu.Lock()
	closed := ep.closed
	nicID := ep.boundNIC
	proto := ep.boundNetProto
	ep.mu.Unlock()
	if closed {
		return 0, &tcpip.ErrClosedForSend{}
	}

	var remote tcpip.LinkAddress
	if to := opts.To; to != nil {
		remote = tcpip.LinkAddress(to.Addr)

		if n := to.NIC; n != 0 {
			nicID = n
		}

		if p := to.Port; p != 0 {
			proto = tcpip.NetworkProtocolNumber(p)
		}
	}

	if nicID == 0 {
		return 0, &tcpip.ErrInvalidOptionValue{}
	}

	// TODO(https://gvisor.dev/issue/6538): Avoid this allocation.
	payloadBytes := make(buffer.View, p.Len())
	if _, err := io.ReadFull(p, payloadBytes); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}

	if err := func() tcpip.Error {
		if ep.cooked {
			return ep.stack.WritePacketToRemote(nicID, remote, proto, payloadBytes.ToVectorisedView())
		}
		return ep.stack.WriteRawPacket(nicID, proto, payloadBytes.ToVectorisedView())
	}(); err != nil {
		return 0, err
	}
	return int64(len(payloadBytes)), nil
}

// Disconnect implements tcpip.Endpoint.Disconnect. Packet sockets cannot be
// disconnected, and this function always returns tpcip.ErrNotSupported.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect implements tcpip.Endpoint.Connect. Packet sockets cannot be
// connected, and this function always returnes *tcpip.ErrNotSupported.
func (*endpoint) Connect(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Shutdown implements tcpip.Endpoint.Shutdown. Packet sockets cannot be used
// with Shutdown, and this function always returns *tcpip.ErrNotSupported.
func (*endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Listen implements tcpip.Endpoint.Listen. Packet sockets cannot be used with
// Listen, and this function always returns *tcpip.ErrNotSupported.
func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept implements tcpip.Endpoint.Accept. Packet sockets cannot be used with
// Accept, and this function always returns *tcpip.ErrNotSupported.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

// Bind implements tcpip.Endpoint.Bind.
func (ep *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	// "By default, all packets of the specified protocol type are passed
	// to a packet socket.  To get packets only from a specific interface
	// use bind(2) specifying an address in a struct sockaddr_ll to bind
	// the packet socket  to  an interface.  Fields used for binding are
	// sll_family (should be AF_PACKET), sll_protocol, and sll_ifindex."
	// - packet(7).

	ep.mu.Lock()
	defer ep.mu.Unlock()

	netProto := tcpip.NetworkProtocolNumber(addr.Port)
	if netProto == 0 {
		// Do not allow unbinding the network protocol.
		netProto = ep.boundNetProto
	}

	if ep.boundNIC == addr.NIC && ep.boundNetProto == netProto {
		// Already bound to the requested NIC and network protocol.
		return nil
	}

	// TODO(https://gvisor.dev/issue/6618): Unregister after registering the new
	// binding.
	ep.stack.UnregisterPacketEndpoint(ep.boundNIC, ep.boundNetProto, ep)
	ep.boundNIC = 0
	ep.boundNetProto = 0

	// Bind endpoint to receive packets from specific interface.
	if err := ep.stack.RegisterPacketEndpoint(addr.NIC, netProto, ep); err != nil {
		return err
	}

	ep.boundNIC = addr.NIC
	ep.boundNetProto = netProto
	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (ep *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  ep.boundNIC,
		Port: uint16(ep.boundNetProto),
	}, nil
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	// Even a connected socket doesn't return a remote address.
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

// Readiness implements tcpip.Endpoint.Readiness.
func (ep *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.WritableEvents & mask

	// Determine whether the endpoint is readable.
	if (mask & waiter.ReadableEvents) != 0 {
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() || ep.rcvClosed {
			result |= waiter.ReadableEvents
		}
		ep.rcvMu.Unlock()
	}

	return result
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt. Packet sockets cannot be
// used with SetSockOpt, and this function always returns
// *tcpip.ErrNotSupported.
func (ep *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (*endpoint) SetSockOptInt(tcpip.SockOptInt, int) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (ep *endpoint) LastError() tcpip.Error {
	ep.lastErrorMu.Lock()
	defer ep.lastErrorMu.Unlock()

	err := ep.lastError
	ep.lastError = nil
	return err
}

// UpdateLastError implements tcpip.SocketOptionsHandler.UpdateLastError.
func (ep *endpoint) UpdateLastError(err tcpip.Error) {
	ep.lastErrorMu.Lock()
	ep.lastError = err
	ep.lastErrorMu.Unlock()
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*endpoint) GetSockOpt(tcpip.GettableSocketOption) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (ep *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() {
			p := ep.rcvList.Front()
			v = p.data.Size()
		}
		ep.rcvMu.Unlock()
		return v, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// HandlePacket implements stack.PacketEndpoint.HandlePacket.
func (ep *endpoint) HandlePacket(nicID tcpip.NICID, _ tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	ep.rcvMu.Lock()

	// Drop the packet if our buffer is currently full.
	if ep.rcvClosed {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := ep.ops.GetReceiveBufferSize()
	if ep.rcvDisabled || ep.rcvBufSize >= int(rcvBufSize) {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := ep.rcvBufSize == 0

	rcvdPkt := packet{
		packetInfo: tcpip.LinkPacketInfo{
			Protocol: netProto,
			PktType:  pkt.PktType,
		},
		senderAddr: tcpip.FullAddress{
			NIC: nicID,
		},
		receivedAt: ep.stack.Clock().Now(),
	}

	if !pkt.LinkHeader().View().IsEmpty() {
		hdr := header.Ethernet(pkt.LinkHeader().View())
		rcvdPkt.senderAddr.Addr = tcpip.Address(hdr.SourceAddress())
	}

	if ep.cooked {
		// Cooked packet endpoints don't include the link-headers in received
		// packets.
		if v := pkt.NetworkHeader().View(); !v.IsEmpty() {
			rcvdPkt.data.AppendView(v)
		}
		if v := pkt.TransportHeader().View(); !v.IsEmpty() {
			rcvdPkt.data.AppendView(v)
		}
		rcvdPkt.data.Append(pkt.Data().ExtractVV())
	} else {
		// Raw packet endpoints include link-headers in received packets.
		rcvdPkt.data = buffer.NewVectorisedView(pkt.Size(), pkt.Views())
	}

	ep.rcvList.PushBack(&rcvdPkt)
	ep.rcvBufSize += rcvdPkt.data.Size()

	ep.rcvMu.Unlock()
	ep.stats.PacketsReceived.Increment()
	// Notify waiters that there's data to be read.
	if wasEmpty {
		ep.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

// State implements socket.Socket.State.
func (*endpoint) State() uint32 {
	return 0
}

// Info returns a copy of the endpoint info.
func (ep *endpoint) Info() tcpip.EndpointInfo {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return &stack.TransportEndpointInfo{NetProto: ep.boundNetProto}
}

// Stats returns a pointer to the endpoint stats.
func (ep *endpoint) Stats() tcpip.EndpointStats {
	return &ep.stats
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (*endpoint) SetOwner(tcpip.PacketOwner) {}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (ep *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &ep.ops
}
