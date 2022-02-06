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

// Package udp contains the implementation of the UDP transport protocol.
package udp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ProtocolNumber is the udp protocol number.
	ProtocolNumber = header.UDPProtocolNumber

	// MinBufferSize is the smallest size of a receive or send buffer.
	MinBufferSize = 4 << 10 // 4KiB bytes.

	// DefaultSendBufferSize is the default size of the send buffer for
	// an endpoint.
	DefaultSendBufferSize = 32 << 10 // 32KiB

	// DefaultReceiveBufferSize is the default size of the receive buffer
	// for an endpoint.
	DefaultReceiveBufferSize = 32 << 10 // 32KiB

	// MaxBufferSize is the largest size a receive/send buffer can grow to.
	MaxBufferSize = 4 << 20 // 4MiB
)

type protocol struct {
	stack *stack.Stack
}

// Number returns the udp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new udp endpoint.
func (p *protocol) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return newEndpoint(p.stack, netProto, waiterQueue), nil
}

// NewRawEndpoint creates a new raw UDP endpoint. It implements
// stack.TransportProtocol.NewRawEndpoint.
func (p *protocol) NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, netProto, header.UDPProtocolNumber, waiterQueue)
}

// MinimumPacketSize returns the minimum valid udp packet size.
func (*protocol) MinimumPacketSize() int {
	return header.UDPMinimumSize
}

// ParsePorts returns the source and destination ports stored in the given udp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err tcpip.Error) {
	h := header.UDP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// HandleUnknownDestinationPacket handles packets that are targeted at this
// protocol but don't match any existing endpoint.
func (p *protocol) HandleUnknownDestinationPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		p.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return stack.UnknownDestinationPacketMalformed
	}

	if !verifyChecksum(hdr, pkt) {
		p.stack.Stats().UDP.ChecksumErrors.Increment()
		return stack.UnknownDestinationPacketMalformed
	}

	return stack.UnknownDestinationPacketUnhandled
}

// SetOption implements stack.TransportProtocol.SetOption.
func (*protocol) SetOption(tcpip.SettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// Option implements stack.TransportProtocol.Option.
func (*protocol) Option(tcpip.GettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.TransportProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	return parse.UDP(pkt)
}

// NewProtocol returns a UDP transport protocol.
func NewProtocol(s *stack.Stack) stack.TransportProtocol {
	return &protocol{stack: s}
}
