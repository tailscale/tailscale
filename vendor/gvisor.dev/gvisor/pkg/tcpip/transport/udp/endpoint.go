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

package udp

import (
	"fmt"
	"io"
	"time"

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
type udpPacket struct {
	udpPacketEntry
	netProto           tcpip.NetworkProtocolNumber
	senderAddress      tcpip.FullAddress
	destinationAddress tcpip.FullAddress
	packetInfo         tcpip.IPPacketInfo
	pkt                *stack.PacketBuffer
	receivedAt         time.Time `state:".(int64)"`
	// tos stores either the receiveTOS or receiveTClass value.
	tos uint8
}

// endpoint represents a UDP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized.
//
// It implements tcpip.Endpoint.
//
// +stateify savable
type endpoint struct {
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack `state:"manual"`
	waiterQueue *waiter.Queue
	uniqueID    uint64
	net         network.Endpoint
	stats       tcpip.TransportEndpointStats
	ops         tcpip.SocketOptions

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu      sync.Mutex `state:"nosave"`
	rcvReady   bool
	rcvList    udpPacketList
	rcvBufSize int
	rcvClosed  bool

	lastErrorMu sync.Mutex `state:"nosave"`
	lastError   tcpip.Error

	// The following fields are protected by the mu mutex.
	mu        sync.RWMutex `state:"nosave"`
	portFlags ports.Flags

	// Values used to reserve a port or register a transport endpoint.
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	readShutdown bool

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// frozen indicates if the packets should be delivered to the endpoint
	// during restore.
	frozen bool

	localPort  uint16
	remotePort uint16
}

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       s,
		waiterQueue: waiterQueue,
		uniqueID:    s.UniqueID(),
	}
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetSendBufferSize(32*1024, false /* notify */)
	e.ops.SetReceiveBufferSize(32*1024, false /* notify */)
	e.net.Init(s, netProto, header.UDPProtocolNumber, &e.ops)

	// Override with stack defaults.
	var ss tcpip.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}

	var rs tcpip.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false /* notify */)
	}

	return e
}

// UniqueID implements stack.TransportEndpoint.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

func (e *endpoint) LastError() tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()

	err := e.lastError
	e.lastError = nil
	return err
}

// UpdateLastError implements tcpip.SocketOptionsHandler.
func (e *endpoint) UpdateLastError(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
}

// Abort implements stack.TransportEndpoint.
func (e *endpoint) Abort() {
	e.Close()
}

// Close puts the endpoint in a closed state and frees all resources
// associated with it.
func (e *endpoint) Close() {
	e.mu.Lock()

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial:
	case transport.DatagramEndpointStateClosed:
		e.mu.Unlock()
		return
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		id := e.net.Info().ID
		id.LocalPort = e.localPort
		id.RemotePort = e.remotePort
		e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, id, e, e.boundPortFlags, e.boundBindToDevice)
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
		p.pkt.DecRef()
	}
	e.rcvMu.Unlock()

	e.net.Shutdown()
	e.net.Close()
	e.readShutdown = true
	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// ModerateRecvBuf implements tcpip.Endpoint.
func (*endpoint) ModerateRecvBuf(int) {}

// Read implements tcpip.Endpoint.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if err := e.LastError(); err != nil {
		return tcpip.ReadResult{}, err
	}

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
		defer p.pkt.DecRef()
		e.rcvBufSize -= p.pkt.Data().Size()
	}
	e.rcvMu.Unlock()

	// Control Messages
	cm := tcpip.ControlMessages{
		HasTimestamp: true,
		Timestamp:    p.receivedAt,
	}

	switch p.netProto {
	case header.IPv4ProtocolNumber:
		if e.ops.GetReceiveTOS() {
			cm.HasTOS = true
			cm.TOS = p.tos
		}

		if e.ops.GetReceivePacketInfo() {
			cm.HasIPPacketInfo = true
			cm.PacketInfo = p.packetInfo
		}
	case header.IPv6ProtocolNumber:
		if e.ops.GetReceiveTClass() {
			cm.HasTClass = true
			// Although TClass is an 8-bit value it's read in the CMsg as a uint32.
			cm.TClass = uint32(p.tos)
		}

		if e.ops.GetIPv6ReceivePacketInfo() {
			cm.HasIPv6PacketInfo = true
			cm.IPv6PacketInfo = tcpip.IPv6PacketInfo{
				NIC:  p.packetInfo.NIC,
				Addr: p.packetInfo.DestinationAddr,
			}
		}
	default:
		panic(fmt.Sprintf("unrecognized network protocol = %d", p.netProto))
	}

	if e.ops.GetReceiveOriginalDstAddress() {
		cm.HasOriginalDstAddress = true
		cm.OriginalDstAddress = p.destinationAddress
	}

	// Read Result
	res := tcpip.ReadResult{
		Total:           p.pkt.Data().Size(),
		ControlMessages: cm,
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = p.senderAddress
	}

	n, err := p.pkt.Data().ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, &tcpip.ErrBadBuffer{}
	}
	res.Count = n
	return res, nil
}

// prepareForWriteInner prepares the endpoint for sending data. In particular,
// it binds it if it's still in the initial state. To do so, it must first
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

func (e *endpoint) prepareForWrite(p tcpip.Payloader, opts tcpip.WriteOptions) (udpPacketInfo, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Prepare for write.
	for {
		retry, err := e.prepareForWriteInner(opts.To)
		if err != nil {
			return udpPacketInfo{}, err
		}

		if !retry {
			break
		}
	}

	dst, connected := e.net.GetRemoteAddress()
	dst.Port = e.remotePort
	if opts.To != nil {
		if opts.To.Port == 0 {
			// Port 0 is an invalid port to send to.
			return udpPacketInfo{}, &tcpip.ErrInvalidEndpointState{}
		}

		dst = *opts.To
	} else if !connected {
		return udpPacketInfo{}, &tcpip.ErrDestinationRequired{}
	}

	ctx, err := e.net.AcquireContextForWrite(opts)
	if err != nil {
		return udpPacketInfo{}, err
	}

	// TODO(https://gvisor.dev/issue/6538): Avoid this allocation.
	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		ctx.Release()
		return udpPacketInfo{}, &tcpip.ErrBadBuffer{}
	}
	if len(v) > header.UDPMaximumPacketSize {
		// Payload can't possibly fit in a packet.
		so := e.SocketOptions()
		if so.GetRecvError() {
			so.QueueLocalErr(
				&tcpip.ErrMessageTooLong{},
				e.net.NetProto(),
				header.UDPMaximumPacketSize,
				dst,
				v,
			)
		}
		ctx.Release()
		return udpPacketInfo{}, &tcpip.ErrMessageTooLong{}
	}

	return udpPacketInfo{
		ctx:        ctx,
		data:       v,
		localPort:  e.localPort,
		remotePort: dst.Port,
	}, nil
}

func (e *endpoint) write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// Do not hold lock when sending as loopback is synchronous and if the UDP
	// datagram ends up generating an ICMP response then it can result in a
	// deadlock where the ICMP response handling ends up acquiring this endpoint's
	// mutex using e.mu.RLock() in endpoint.HandleControlPacket which can cause a
	// deadlock if another caller is trying to acquire e.mu in exclusive mode w/
	// e.mu.Lock(). Since e.mu.Lock() prevents any new read locks to ensure the
	// lock can be eventually acquired.
	//
	// See: https://golang.org/pkg/sync/#RWMutex for details on why recursive read
	// locking is prohibited.

	if err := e.LastError(); err != nil {
		return 0, err
	}

	udpInfo, err := e.prepareForWrite(p, opts)
	if err != nil {
		return 0, err
	}
	defer udpInfo.ctx.Release()

	pktInfo := udpInfo.ctx.PacketInfo()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(pktInfo.MaxHeaderLength),
		Data:               udpInfo.data.ToVectorisedView(),
	})
	defer pkt.DecRef()

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: udpInfo.localPort,
		DstPort: udpInfo.remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if pktInfo.RequiresTXTransportChecksum &&
		(!e.ops.GetNoChecksum() || pktInfo.NetProto == header.IPv6ProtocolNumber) {
		udp.SetChecksum(^udp.CalculateChecksum(header.ChecksumCombine(
			header.PseudoHeaderChecksum(ProtocolNumber, pktInfo.LocalAddress, pktInfo.RemoteAddress, length),
			pkt.Data().AsRange().Checksum(),
		)))
	}
	if err := udpInfo.ctx.WritePacket(pkt, false /* headerIncluded */); err != nil {
		e.stack.Stats().UDP.PacketSendErrors.Increment()
		return 0, err
	}

	// Track count of packets sent.
	e.stack.Stats().UDP.PacketsSent.Increment()
	return int64(len(udpInfo.data)), nil
}

// OnReuseAddressSet implements tcpip.SocketOptionsHandler.
func (e *endpoint) OnReuseAddressSet(v bool) {
	e.mu.Lock()
	e.portFlags.MostRecent = v
	e.mu.Unlock()
}

// OnReusePortSet implements tcpip.SocketOptionsHandler.
func (e *endpoint) OnReusePortSet(v bool) {
	e.mu.Lock()
	e.portFlags.LoadBalanced = v
	e.mu.Unlock()
}

// SetSockOptInt implements tcpip.Endpoint.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.net.SetSockOptInt(opt, v)
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

// GetSockOptInt implements tcpip.Endpoint.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.rcvMu.Lock()
		if !e.rcvList.Empty() {
			p := e.rcvList.Front()
			v = p.pkt.Data().Size()
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

// udpPacketInfo holds information needed to send a UDP packet.
type udpPacketInfo struct {
	ctx        network.WriteContext
	data       buffer.View
	localPort  uint16
	remotePort uint16
}

// Disconnect implements tcpip.Endpoint.
func (e *endpoint) Disconnect() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.net.State() != transport.DatagramEndpointStateConnected {
		return nil
	}
	var (
		id  stack.TransportEndpointID
		btd tcpip.NICID
	)

	// We change this value below and we need the old value to unregister
	// the endpoint.
	boundPortFlags := e.boundPortFlags

	// Exclude ephemerally bound endpoints.
	info := e.net.Info()
	info.ID.LocalPort = e.localPort
	info.ID.RemotePort = e.remotePort
	if e.net.WasBound() {
		var err tcpip.Error
		id = stack.TransportEndpointID{
			LocalPort:    info.ID.LocalPort,
			LocalAddress: info.ID.LocalAddress,
		}
		id, btd, err = e.registerWithStack(e.effectiveNetProtos, id)
		if err != nil {
			return err
		}
		boundPortFlags = e.boundPortFlags
	} else {
		if info.ID.LocalPort != 0 {
			// Release the ephemeral port.
			portRes := ports.Reservation{
				Networks:     e.effectiveNetProtos,
				Transport:    ProtocolNumber,
				Addr:         info.ID.LocalAddress,
				Port:         info.ID.LocalPort,
				Flags:        boundPortFlags,
				BindToDevice: e.boundBindToDevice,
				Dest:         tcpip.FullAddress{},
			}
			e.stack.ReleasePort(portRes)
			e.boundPortFlags = ports.Flags{}
		}
	}

	e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, info.ID, e, boundPortFlags, e.boundBindToDevice)
	e.boundBindToDevice = btd
	e.localPort = id.LocalPort
	e.remotePort = id.RemotePort

	e.net.Disconnect()

	return nil
}

// Connect connects the endpoint to its peer. Specifying a NIC is optional.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.net.ConnectAndThen(addr, func(netProto tcpip.NetworkProtocolNumber, previousID, nextID stack.TransportEndpointID) tcpip.Error {
		nextID.LocalPort = e.localPort
		nextID.RemotePort = addr.Port

		// Even if we're connected, this endpoint can still be used to send
		// packets on a different network protocol, so we register both even if
		// v6only is set to false and this is an ipv6 endpoint.
		netProtos := []tcpip.NetworkProtocolNumber{netProto}
		if netProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() {
			netProtos = []tcpip.NetworkProtocolNumber{
				header.IPv4ProtocolNumber,
				header.IPv6ProtocolNumber,
			}
		}

		oldPortFlags := e.boundPortFlags

		nextID, btd, err := e.registerWithStack(netProtos, nextID)
		if err != nil {
			return err
		}

		// Remove the old registration.
		if e.localPort != 0 {
			previousID.LocalPort = e.localPort
			previousID.RemotePort = e.remotePort
			e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, previousID, e, oldPortFlags, e.boundBindToDevice)
		}

		e.localPort = nextID.LocalPort
		e.remotePort = nextID.RemotePort
		e.boundBindToDevice = btd
		e.effectiveNetProtos = netProtos
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
		e.readShutdown = true

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

func (e *endpoint) registerWithStack(netProtos []tcpip.NetworkProtocolNumber, id stack.TransportEndpointID) (stack.TransportEndpointID, tcpip.NICID, tcpip.Error) {
	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	if e.localPort == 0 {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.portFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		port, err := e.stack.ReservePort(e.stack.Rand(), portRes, nil /* testPort */)
		if err != nil {
			return id, bindToDevice, err
		}
		id.LocalPort = port
	}
	e.boundPortFlags = e.portFlags

	err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.boundPortFlags, bindToDevice)
	if err != nil {
		portRes := ports.Reservation{
			Networks:     netProtos,
			Transport:    ProtocolNumber,
			Addr:         id.LocalAddress,
			Port:         id.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: bindToDevice,
			Dest:         tcpip.FullAddress{},
		}
		e.stack.ReleasePort(portRes)
		e.boundPortFlags = ports.Flags{}
	}
	return id, bindToDevice, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) tcpip.Error {
	// Don't allow binding once endpoint is not in the initial state
	// anymore.
	if e.net.State() != transport.DatagramEndpointStateInitial {
		return &tcpip.ErrInvalidEndpointState{}
	}

	err := e.net.BindAndThen(addr, func(boundNetProto tcpip.NetworkProtocolNumber, boundAddr tcpip.Address) tcpip.Error {
		// Expand netProtos to include v4 and v6 if the caller is binding to a
		// wildcard (empty) address, and this is an IPv6 endpoint with v6only
		// set to false.
		netProtos := []tcpip.NetworkProtocolNumber{boundNetProto}
		if boundNetProto == header.IPv6ProtocolNumber && !e.ops.GetV6Only() && boundAddr == "" {
			netProtos = []tcpip.NetworkProtocolNumber{
				header.IPv6ProtocolNumber,
				header.IPv4ProtocolNumber,
			}
		}

		id := stack.TransportEndpointID{
			LocalPort:    addr.Port,
			LocalAddress: boundAddr,
		}
		id, btd, err := e.registerWithStack(netProtos, id)
		if err != nil {
			return err
		}

		e.localPort = id.LocalPort
		e.boundBindToDevice = btd
		e.effectiveNetProtos = netProtos
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

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
func (e *endpoint) Bind(addr tcpip.FullAddress) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.bindLocked(addr)
	if err != nil {
		return err
	}

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr := e.net.GetLocalAddress()
	addr.Port = e.localPort
	return addr, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	addr, connected := e.net.GetRemoteAddress()
	if !connected || e.remotePort == 0 {
		return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
	}

	addr.Port = e.remotePort
	return addr, nil
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.WritableEvents & mask

	// Determine if the endpoint is readable if requested.
	if mask&waiter.ReadableEvents != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.ReadableEvents
		}
		e.rcvMu.Unlock()
	}

	e.lastErrorMu.Lock()
	hasError := e.lastError != nil
	e.lastErrorMu.Unlock()
	if hasError {
		result |= waiter.EventErr
	}
	return result
}

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool {
	if pkt.RXTransportChecksumValidated {
		return true
	}

	// On IPv4, UDP checksum is optional, and a zero value means the transmitter
	// omitted the checksum generation, as per RFC 768:
	//
	//   An all zero transmitted checksum value means that the transmitter
	//   generated  no checksum  (for debugging or for higher level protocols that
	//   don't care).
	//
	// On IPv6, UDP checksum is not optional, as per RFC 2460 Section 8.1:
	//
	//   Unlike IPv4, when UDP packets are originated by an IPv6 node, the UDP
	//   checksum is not optional.
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber && hdr.Checksum() == 0 {
		return true
	}

	netHdr := pkt.Network()
	payloadChecksum := pkt.Data().AsRange().Checksum()
	return hdr.IsChecksumValid(netHdr.SourceAddress(), netHdr.DestinationAddress(), payloadChecksum)
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	// Get the header then trim it from the view.
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}

	if !verifyChecksum(hdr, pkt) {
		e.stack.Stats().UDP.ChecksumErrors.Increment()
		e.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	e.stack.Stats().UDP.PacketsReceived.Increment()
	e.stats.PacketsReceived.Increment()

	e.rcvMu.Lock()
	// Drop the packet if our buffer is currently full.
	if !e.rcvReady || e.rcvClosed {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	rcvBufSize := e.ops.GetReceiveBufferSize()
	if e.frozen || e.rcvBufSize >= int(rcvBufSize) {
		e.rcvMu.Unlock()
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := e.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	packet := &udpPacket{
		netProto: pkt.NetworkProtocolNumber,
		senderAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.RemoteAddress,
			Port: hdr.SourcePort(),
		},
		destinationAddress: tcpip.FullAddress{
			NIC:  pkt.NICID,
			Addr: id.LocalAddress,
			Port: hdr.DestinationPort(),
		},
		pkt: pkt,
	}
	pkt.IncRef()
	e.rcvList.PushBack(packet)
	e.rcvBufSize += pkt.Data().Size()

	// Save any useful information from the network header to the packet.
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		packet.tos, _ = header.IPv4(pkt.NetworkHeader().View()).TOS()
	case header.IPv6ProtocolNumber:
		packet.tos, _ = header.IPv6(pkt.NetworkHeader().View()).TOS()
	}

	// TODO(gvisor.dev/issue/3556): r.LocalAddress may be a multicast or broadcast
	// address. packetInfo.LocalAddr should hold a unicast address that can be
	// used to respond to the incoming packet.
	localAddr := pkt.Network().DestinationAddress()
	packet.packetInfo.LocalAddr = localAddr
	packet.packetInfo.DestinationAddr = localAddr
	packet.packetInfo.NIC = pkt.NICID
	packet.receivedAt = e.stack.Clock().Now()

	e.rcvMu.Unlock()

	// Notify any waiters that there's data to be read now.
	if wasEmpty {
		e.waiterQueue.Notify(waiter.ReadableEvents)
	}
}

func (e *endpoint) onICMPError(err tcpip.Error, transErr stack.TransportError, pkt *stack.PacketBuffer) {
	// Update last error first.
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()

	// Update the error queue if IP_RECVERR is enabled.
	if e.SocketOptions().GetRecvError() {
		// Linux passes the payload without the UDP header.
		var payload []byte
		udp := header.UDP(pkt.Data().AsRange().ToOwnedView())
		if len(udp) >= header.UDPMinimumSize {
			payload = udp.Payload()
		}

		id := e.net.Info().ID
		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:     err,
			Cause:   transErr,
			Payload: payload,
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: id.RemoteAddress,
				Port: e.remotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: id.LocalAddress,
				Port: e.localPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
	}

	// Notify of the error.
	e.waiterQueue.Notify(waiter.EventErr)
}

// HandleError implements stack.TransportEndpoint.
func (e *endpoint) HandleError(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	// TODO(gvisor.dev/issues/5270): Handle all transport errors.
	switch transErr.Kind() {
	case stack.DestinationPortUnreachableTransportError:
		if e.net.State() == transport.DatagramEndpointStateConnected {
			e.onICMPError(&tcpip.ErrConnectionRefused{}, transErr, pkt)
		}
	}
}

// State implements tcpip.Endpoint.
func (e *endpoint) State() uint32 {
	return uint32(e.net.State())
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	info := e.net.Info()
	info.ID.LocalPort = e.localPort
	info.ID.RemotePort = e.remotePort
	return &info
}

// Stats returns a pointer to the endpoint stats.
func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

// Wait implements tcpip.Endpoint.
func (*endpoint) Wait() {}

// SetOwner implements tcpip.Endpoint.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.net.SetOwner(owner)
}

// SocketOptions implements tcpip.Endpoint.
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
