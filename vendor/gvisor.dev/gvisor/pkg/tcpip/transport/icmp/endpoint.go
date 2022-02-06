// Copyright 2018 The gVisor Authors.
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

package icmp

import (
	"fmt"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/tcpip/transport/internal/network"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type icmpPacket struct {
	icmpPacketEntry
	senderAddress tcpip.FullAddress
	data          buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	receivedAt    time.Time             `state:".(int64)"`
}

// endpoint represents an ICMP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// +stateify savable
type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	transProto  tcpip.TransportProtocolNumber
	waiterQueue *waiter.Queue
	uniqueID    uint64
	net         network.Endpoint
	stats       tcpip.TransportEndpointStats
	ops         tcpip.SocketOptions

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu      sync.Mutex `state:"nosave"`
	rcvReady   bool
	rcvList    icmpPacketList
	rcvBufSize int
	rcvClosed  bool

	// The following fields are protected by the mu mutex.
	mu sync.RWMutex `state:"nosave"`
	// frozen indicates if the packets should be delivered to the endpoint
	// during restore.
	frozen bool
	ident  uint16
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	ep := &endpoint{
		stack:       s,
		transProto:  transProto,
		waiterQueue: waiterQueue,
		uniqueID:    s.UniqueID(),
	}
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	ep.ops.SetSendBufferSize(32*1024, false /* notify */)
	ep.ops.SetReceiveBufferSize(32*1024, false /* notify */)
	ep.net.Init(s, netProto, transProto, &ep.ops)

	// Override with stack defaults.
	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}
	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		ep.ops.SetReceiveBufferSize(int64(rs.Default), false /* notify */)
	}
	return ep, nil
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

// Abort implements stack.TransportEndpoint.Abort.
func (e *endpoint) Abort() {
	e.Close()
}

// Close puts the endpoint in a closed state and frees all resources
// associated with it.
func (e *endpoint) Close() {
	notify := func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()

		switch state := e.net.State(); state {
		case transport.DatagramEndpointStateInitial:
		case transport.DatagramEndpointStateClosed:
			return false
		case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
			info := e.net.Info()
			info.ID.LocalPort = e.ident
			e.stack.UnregisterTransportEndpoint([]tcpip.NetworkProtocolNumber{info.NetProto}, e.transProto, info.ID, e, ports.Flags{}, tcpip.NICID(e.ops.GetBindToDevice()))
		default:
			panic(fmt.Sprintf("unhandled state = %s", state))
		}

		e.net.Shutdown()
		e.net.Close()

		e.rcvMu.Lock()
		defer e.rcvMu.Unlock()
		e.rcvClosed = true
		e.rcvBufSize = 0
		for !e.rcvList.Empty() {
			p := e.rcvList.Front()
			e.rcvList.Remove(p)
		}

		return true
	}()

	if notify {
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (*endpoint) ModerateRecvBuf(int) {}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.net.SetOwner(owner)
}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.rcvMu.Lock()

	if e.rcvList.Empty() {
		var err tcpip.Error = &tcpip.ErrWouldBlock{}
		if e.rcvClosed {
			e.stats.ReadErrors.ReadClosed.Increment()
			err = &tcpip.ErrClosedForReceive{}
		}
		e.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	p := e.rcvList.Front()
	if !opts.Peek {
		e.rcvList.Remove(p)
		e.rcvBufSize -= p.data.Size()
	}

	e.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: p.data.Size(),
		ControlMessages: tcpip.ControlMessages{
			HasTimestamp: true,
			Timestamp:    p.receivedAt,
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = p.senderAddress
	}

	n, err := p.data.ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

// prepareForWrite prepares the endpoint for sending data. In particular, it
// binds it if it's still in the initial state. To do so, it must first
// reacquire the mutex in exclusive mode.
//
// Returns true for retry if preparation should be retried.
// +checklocksread:e.mu
func (e *endpoint) prepareForWriteInner(to *tcpip.FullAddress) (retry bool, err tcpip.Error) {
	switch e.net.State() {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateConnected:
		return false, nil
	case transport.DatagramEndpointStateBound:
		if to == nil {
			return false, &tcpip.ErrDestinationRequired{}
		}
		return false, nil
	default:
		return false, &tcpip.ErrInvalidEndpointState{}
	}

	e.mu.RUnlock()
	e.mu.Lock()
	defer e.mu.DowngradeLock()

	// The state changed when we released the shared locked and re-acquired
	// it in exclusive mode. Try again.
	if e.net.State() != transport.DatagramEndpointStateInitial {
		return true, nil
	}

	// The state is still 'initial', so try to bind the endpoint.
	if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
		return false, err
	}

	return true, nil
}

// Write writes data to the endpoint's peer. This method does not block
// if the data cannot be written.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	n, err := e.write(p, opts)
	switch err.(type) {
	case nil:
		e.stats.PacketsSent.Increment()
	case *tcpip.ErrMessageTooLong, *tcpip.ErrInvalidOptionValue:
		e.stats.WriteErrors.InvalidArgs.Increment()
	case *tcpip.ErrClosedForSend:
		e.stats.WriteErrors.WriteClosed.Increment()
	case *tcpip.ErrInvalidEndpointState:
		e.stats.WriteErrors.InvalidEndpointState.Increment()
	case *tcpip.ErrNoRoute, *tcpip.ErrBroadcastDisabled, *tcpip.ErrNetworkUnreachable:
		// Errors indicating any problem with IP routing of the packet.
		e.stats.SendErrors.NoRoute.Increment()
	default:
		// For all other errors when writing to the network layer.
		e.stats.SendErrors.SendToNetworkFailed.Increment()
	}
	return n, err
}

func (e *endpoint) prepareForWrite(opts tcpip.WriteOptions) (network.WriteContext, uint16, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Prepare for write.
	for {
		retry, err := e.prepareForWriteInner(opts.To)
		if err != nil {
			return network.WriteContext{}, 0, err
		}

		if !retry {
			break
		}
	}

	ctx, err := e.net.AcquireContextForWrite(opts)
	return ctx, e.ident, err
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	ctx, ident, err := e.prepareForWrite(opts)
	if err != nil {
		return 0, err
	}
	defer ctx.Release()

	// TODO(https://gvisor.dev/issue/6538): Avoid this allocation.
	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}

	switch netProto, pktInfo := e.net.NetProto(), ctx.PacketInfo(); netProto {
	case header.IPv4ProtocolNumber:
		if err := send4(e.stack, &ctx, ident, v, pktInfo.MaxHeaderLength); err != nil {
			return 0, err
		}

	case header.IPv6ProtocolNumber:
		if err := send6(e.stack, &ctx, ident, v, pktInfo.LocalAddress, pktInfo.RemoteAddress, pktInfo.MaxHeaderLength); err != nil {
			return 0, err
		}
	default:
		panic(fmt.Sprintf("unhandled network protocol = %d", netProto))
	}

	return int64(len(v)), nil
}

var _ tcpip.SocketOptionsHandler = (*endpoint)(nil)

// HasNIC implements tcpip.SocketOptionsHandler.
func (e *endpoint) HasNIC(id int32) bool {
	return e.stack.HasNIC(tcpip.NICID(id))
}

// SetSockOpt implements tcpip.Endpoint.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return e.net.SetSockOpt(opt)
}

// SetSockOptInt implements tcpip.Endpoint.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.net.SetSockOptInt(opt, v)
}

// GetSockOptInt implements tcpip.Endpoint.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.data.Size()
		}
		e.rcvMu.Unlock()
		return v, nil

	default:
		return e.net.GetSockOptInt(opt)
	}
}

// GetSockOpt implements tcpip.Endpoint.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return e.net.GetSockOpt(opt)
}

func send4(s *stack.Stack, ctx *network.WriteContext, ident uint16, data buffer.View, maxHeaderLength uint16) tcpip.Error {
	if len(data) < header.ICMPv4MinimumSize {
		log.Infof("len(data) is smaller than min size")
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv4MinimumSize + int(maxHeaderLength),
	})
	defer pkt.DecRef()

	icmpv4 := header.ICMPv4(pkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	copy(icmpv4, data)
	// Set the ident to the user-specified port. Sequence number should
	// already be set by the user.
	icmpv4.SetIdent(ident)
	data = data[header.ICMPv4MinimumSize:]

	// Linux performs these basic checks.
	if icmpv4.Type() != header.ICMPv4Echo || icmpv4.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	icmpv4.SetChecksum(0)
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))
	pkt.Data().AppendView(data)

	// Because this icmp endpoint is implemented in the transport layer, we can
	// only increment the 'stack-wide' stats but we can't increment the
	// 'per-NetworkEndpoint' stats.
	stats := s.Stats().ICMP.V4.PacketsSent

	if err := ctx.WritePacket(pkt, false /* headerIncluded */); err != nil {
		stats.Dropped.Increment()
		return err
	}

	stats.EchoRequest.Increment()
	return nil
}

func send6(s *stack.Stack, ctx *network.WriteContext, ident uint16, data buffer.View, src, dst tcpip.Address, maxHeaderLength uint16) tcpip.Error {
	if len(data) < header.ICMPv6EchoMinimumSize {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv6MinimumSize + int(maxHeaderLength),
	})
	defer pkt.DecRef()

	icmpv6 := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6MinimumSize))
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	copy(icmpv6, data)
	// Set the ident. Sequence number is provided by the user.
	icmpv6.SetIdent(ident)
	data = data[header.ICMPv6MinimumSize:]

	if icmpv6.Type() != header.ICMPv6EchoRequest || icmpv6.Code() != 0 {
		return &tcpip.ErrInvalidEndpointState{}
	}

	pkt.Data().AppendView(data)
	dataRange := pkt.Data().AsRange()
	icmpv6.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpv6,
		Src:         src,
		Dst:         dst,
		PayloadCsum: dataRange.Checksum(),
		PayloadLen:  dataRange.Size(),
	}))

	// Because this icmp endpoint is implemented in the transport layer, we can
	// only increment the 'stack-wide' stats but we can't increment the
	// 'per-NetworkEndpoint' stats.
	stats := s.Stats().ICMP.V6.PacketsSent

	if err := ctx.WritePacket(pkt, false /* headerIncluded */); err != nil {
		stats.Dropped.Increment()
		return err
	}

	stats.EchoRequest.Increment()
	return nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.net.ConnectAndThen(addr, func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error {
		nextID.LocalPort = e.ident

		nextID, err := e.registerWithStack(netProto, nextID)
		if err != nil {
			return err
		}

		e.ident = nextID.LocalPort
		return nil
	})
	if err != nil {
		return err
	}

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) tcpip.Error {
	return &tcpip.ErrInvalidEndpointState{}
}

// Shutdown closes the read and/or write end of the endpoint connection
// to its peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
		return &tcpip.ErrNotConnected{}
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}

	if flags&tcpip.ShutdownWrite != 0 {
		if err := e.net.Shutdown(); err != nil {
			return err
		}
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.ReadableEvents)
		}
	}

	return nil
}

// Listen is not supported by UDP, it just fails.
func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept is not supported by UDP, it just fails.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (e *endpoint) registerWithStack(netProto tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.Error) {
	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	if id.LocalPort != 0 {
		// The endpoint already has a local port, just attempt to
		// register it.
		return id, e.stack.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{netProto}, e.transProto, id, e, ports.Flags{}, bindToDevice)
	}

	// We need to find a port for the endpoint.
	_, err := e.stack.PickEphemeralPort(e.stack.Rand(), func(p uint16) (bool, tcpip.Error) {
		id.LocalPort = p
		err := e.stack.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{netProto}, e.transProto, id, e, ports.Flags{}, bindToDevice)
		switch err.(type) {
		case nil:
			return true, nil
		case *tcpip.ErrPortInUse:
			return false, nil
		default:
			return false, err
		}
	})

	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.net.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	err := e.net.BindAndThen(addr, func(boundNetProto tcpip.NetworkProtocolNumber, boundAddr tcpip.Address) tcpip.Error {
		id := stack.TransportEndpointID{
			LocalPort:    addr.Port,
			LocalAddress: addr.Addr,
		}
		id, err := e.registerWithStack(boundNetProto, id)
		if err != nil {
			return err
		}

		e.ident = id.LocalPort
		return nil
	})
	if err != nil {
		return err
	}

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (e *endpoint) isBroadcastOrMulticast(nicID tcpip.NICID, addr tcpip.Address) bool {
	return addr == header.IPv4Broadcast ||
		header.IsV4MulticastAddress(addr) ||
		header.IsV6MulticastAddress(addr) ||
		e.stack.IsSubnetBroadcast(nicID, e.net.NetProto(), addr)
}

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	if len(addr.Addr) != 0 && e.isBroadcastOrMulticast(addr.NIC, addr.Addr) {
		return &tcpip.ErrBadLocalAddress{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	return e.bindLocked(addr)
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.net.GetLocalAddress()
	addr.Port = e.ident
	return addr, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if addr, connected := e.net.GetRemoteAddress(); connected {
		return addr, nil
	}

	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.WritableEvents & mask

	// Determine if the endpoint is readable if requested.
	if (mask & waiter.ReadableEvents) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	return result
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	// Only accept echo replies.
	switch e.net.NetProto() {
	case header.IPv4ProtocolNumber:
		h := header.ICMPv4(pkt.TransportHeader().View())
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	case header.IPv6ProtocolNumber:
		h := header.ICMPv6(pkt.TransportHeader().View())
		if len(h) < header.ICMPv6MinimumSize || h.Type() != header.ICMPv6EchoReply {
			e.stack.Stats().DroppedPackets.Increment()
			e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
			return
		}
	}

	e.rcvMu.Lock()

	// Drop the packet if our buffer is currently full.
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &icmpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
		},
	}

	// ICMP socket's data includes ICMP header.
	packet.data = pkt.TransportHeader().View().ToVectorisedView()
	packet.data.Append(pkt.Data().ExtractVV())

	e.rcvList.PushBack(packet)
	e.rcvBufSize += packet.data.Size()

	packet.receivedAt = e.stack.Clock().Now()

	e.rcvMu.Unlock()
	e.stats.PacketsReceived.Increment()
	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

// HandleError implements stack.TransportEndpoint.
func (*endpoint) HandleError(stack.TransportError, *stack.PacketBuffer) {}

// State implements tcpip.Endpoint.State. The ICMP endpoint currently doesn't
// expose internal socket state.
func (e *endpoint) State() uint32 {
	return 0
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ret := e.net.Info()
	ret.ID.LocalPort = e.ident
	return &ret
}

// Stats returns a pointer to the endpoint stats.
func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

// Wait implements stack.TransportEndpoint.Wait.
func (*endpoint) Wait() {}

// LastError implements tcpip.Endpoint.LastError.
func (*endpoint) LastError() tcpip.Error {
	return nil
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (e *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

// freeze prevents any more packets from being delivered to the endpoint.
func (e *endpoint) freeze() {
	e.mu.Lock()
	e.frozen = true
	e.mu.Unlock()
}

// thaw unfreezes a previously frozen endpoint using endpoint.freeze() allows
// new packets to be delivered again.
func (e *endpoint) thaw() {
	e.mu.Lock()
	e.frozen = false
	e.mu.Unlock()
}
