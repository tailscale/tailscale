// Copyright 2021 The gVisor Authors.
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

// Package noop contains an endpoint that implements all tcpip.Endpoint
// functions as noops.
package noop

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// endpoint can be created, but all interactions have no effect or
// return errors.
//
// +stateify savable
type endpoint struct {
	tcpip.DefaultSocketOptionsHandler
	ops tcpip.SocketOptions
}

// New returns an initialized noop endpoint.
func New(stk *stack.Stack) tcpip.Endpoint {
	// ep.ops must be in a valid, initialized state for callers of
	// ep.SocketOptions.
	var ep endpoint
	ep.ops.InitHandler(&ep, stk, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	return &ep
}

// Abort implements stack.TransportEndpoint.Abort.
func (*endpoint) Abort() {
	// No-op.
}

// Close implements tcpip.Endpoint.Close.
func (*endpoint) Close() {
	// No-op.
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (*endpoint) ModerateRecvBuf(int) {
	// No-op.
}

func (*endpoint) SetOwner(tcpip.PacketOwner) {
	// No-op.
}

// Read implements tcpip.Endpoint.Read.
func (*endpoint) Read(io.Writer, tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	return tcpip.ReadResult{}, &tcpip.ErrNotPermitted{}
}

// Write implements tcpip.Endpoint.Write.
func (*endpoint) Write(tcpip.Payloader, tcpip.WriteOptions) (int64, tcpip.Error) {
	return 0, &tcpip.ErrNotPermitted{}
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect implements tcpip.Endpoint.Connect.
func (*endpoint) Connect(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

// Shutdown implements tcpip.Endpoint.Shutdown.
func (*endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

// Listen implements tcpip.Endpoint.Listen.
func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept implements tcpip.Endpoint.Accept.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

// Bind implements tcpip.Endpoint.Bind.
func (*endpoint) Bind(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (*endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotSupported{}
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

// Readiness implements tcpip.Endpoint.Readiness.
func (*endpoint) Readiness(waiter.EventMask) waiter.EventMask {
	return 0
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (*endpoint) SetSockOpt(tcpip.SettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*endpoint) SetSockOptInt(tcpip.SockOptInt, int) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*endpoint) GetSockOpt(tcpip.GettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (*endpoint) GetSockOptInt(tcpip.SockOptInt) (int, tcpip.Error) {
	return 0, &tcpip.ErrUnknownProtocolOption{}
}

// HandlePacket implements stack.RawTransportEndpoint.HandlePacket.
func (*endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	panic(fmt.Sprintf("unreachable: noop.endpoint should never be registered, but got packet: %+v", pkt))
}

// State implements socket.Socket.State.
func (*endpoint) State() uint32 {
	return 0
}

// Wait implements stack.TransportEndpoint.Wait.
func (*endpoint) Wait() {
	// No-op.
}

// LastError implements tcpip.Endpoint.LastError.
func (*endpoint) LastError() tcpip.Error {
	return nil
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (ep *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &ep.ops
}

// Info implements tcpip.Endpoint.Info.
func (*endpoint) Info() tcpip.EndpointInfo {
	return &stack.TransportEndpointInfo{}
}

// Stats returns a pointer to the endpoint stats.
func (*endpoint) Stats() tcpip.EndpointStats {
	return &tcpip.TransportEndpointStats{}
}
