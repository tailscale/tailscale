// Copyright 2020 The gVisor Authors.
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

// Package parse provides utilities to parse packets.
package parse

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ARP populates pkt's network header with an ARP header found in
// pkt.Data.
//
// Returns true if the header was successfully parsed.
func ARP(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.NetworkHeader().Consume(header.ARPSize)
	if ok {
		pkt.NetworkProtocolNumber = header.ARPProtocolNumber
	}
	return ok
}

// IPv4 parses an IPv4 packet found in pkt.Data and populates pkt's network
// header with the IPv4 header.
//
// Returns true if the header was successfully parsed.
func IPv4(pkt *stack.PacketBuffer) bool {
	hdr, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return false
	}
	ipHdr := header.IPv4(hdr)

	// Header may have options, determine the true header length.
	headerLen := int(ipHdr.HeaderLength())
	if headerLen < header.IPv4MinimumSize {
		// TODO(gvisor.dev/issue/2404): Per RFC 791, IHL needs to be at least 5 in
		// order for the packet to be valid. Figure out if we want to reject this
		// case.
		headerLen = header.IPv4MinimumSize
	}
	hdr, ok = pkt.NetworkHeader().Consume(headerLen)
	if !ok {
		return false
	}
	ipHdr = header.IPv4(hdr)
	length := int(ipHdr.TotalLength()) - len(hdr)
	if length < 0 {
		return false
	}

	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.Data().CapLength(length)
	return true
}

// IPv6 parses an IPv6 packet found in pkt.Data and populates pkt's network
// header with the IPv6 header.
func IPv6(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, fragID uint32, fragOffset uint16, fragMore bool, ok bool) {
	hdr, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return 0, 0, 0, false, false
	}
	ipHdr := header.IPv6(hdr)

	// Create a VV to parse the packet. We don't plan to modify anything here.
	// dataVV consists of:
	// - Any IPv6 header bytes after the first 40 (i.e. extensions).
	// - The transport header, if present.
	// - Any other payload data.
	views := [8]buffer.View{}
	dataVV := buffer.NewVectorisedView(0, views[:0])
	dataVV.AppendViews(pkt.Data().Views())
	dataVV.TrimFront(header.IPv6MinimumSize)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), dataVV)

	// Iterate over the IPv6 extensions to find their length.
	var nextHdr tcpip.TransportProtocolNumber
	var extensionsSize int

traverseExtensions:
	for {
		extHdr, done, err := it.Next()
		if err != nil {
			break
		}

		// If we exhaust the extension list, the entire packet is the IPv6 header
		// and (possibly) extensions.
		if done {
			extensionsSize = dataVV.Size()
			break
		}

		switch extHdr := extHdr.(type) {
		case header.IPv6FragmentExtHdr:
			if extHdr.IsAtomic() {
				// This fragment extension header indicates that this packet is an
				// atomic fragment. An atomic fragment is a fragment that contains
				// all the data required to reassemble a full packet. As per RFC 6946,
				// atomic fragments must not interfere with "normal" fragmented traffic
				// so we skip processing the fragment instead of feeding it through the
				// reassembly process below.
				continue
			}

			if fragID == 0 && fragOffset == 0 && !fragMore {
				fragID = extHdr.ID()
				fragOffset = extHdr.FragmentOffset()
				fragMore = extHdr.More()
			}
			rawPayload := it.AsRawHeader(true /* consume */)
			extensionsSize = dataVV.Size() - rawPayload.Buf.Size()
			break traverseExtensions

		case header.IPv6RawPayloadHeader:
			// We've found the payload after any extensions.
			extensionsSize = dataVV.Size() - extHdr.Buf.Size()
			nextHdr = tcpip.TransportProtocolNumber(extHdr.Identifier)
			break traverseExtensions

		default:
			// Any other extension is a no-op, keep looping until we find the payload.
		}
	}

	// Put the IPv6 header with extensions in pkt.NetworkHeader().
	hdr, ok = pkt.NetworkHeader().Consume(header.IPv6MinimumSize + extensionsSize)
	if !ok {
		panic(fmt.Sprintf("pkt.Data should have at least %d bytes, but only has %d.", header.IPv6MinimumSize+extensionsSize, pkt.Data().Size()))
	}
	ipHdr = header.IPv6(hdr)
	pkt.Data().CapLength(int(ipHdr.PayloadLength()))
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber

	return nextHdr, fragID, fragOffset, fragMore, true
}

// UDP parses a UDP packet found in pkt.Data and populates pkt's transport
// header with the UDP header.
//
// Returns true if the header was successfully parsed.
func UDP(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.TransportHeader().Consume(header.UDPMinimumSize)
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	return ok
}

// TCP parses a TCP packet found in pkt.Data and populates pkt's transport
// header with the TCP header.
//
// Returns true if the header was successfully parsed.
func TCP(pkt *stack.PacketBuffer) bool {
	// TCP header is variable length, peek at it first.
	hdrLen := header.TCPMinimumSize
	hdr, ok := pkt.Data().PullUp(hdrLen)
	if !ok {
		return false
	}

	// If the header has options, pull those up as well.
	if offset := int(header.TCP(hdr).DataOffset()); offset > header.TCPMinimumSize && offset <= pkt.Data().Size() {
		// TODO(gvisor.dev/issue/2404): Figure out whether to reject this kind of
		// packets.
		hdrLen = offset
	}

	_, ok = pkt.TransportHeader().Consume(hdrLen)
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	return ok
}

// ICMPv4 populates the packet buffer's transport header with an ICMPv4 header,
// if present.
//
// Returns true if an ICMPv4 header was successfully parsed.
func ICMPv4(pkt *stack.PacketBuffer) bool {
	if _, ok := pkt.TransportHeader().Consume(header.ICMPv4MinimumSize); ok {
		pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
		return true
	}
	return false
}

// ICMPv6 populates the packet buffer's transport header with an ICMPv4 header,
// if present.
//
// Returns true if an ICMPv6 header was successfully parsed.
func ICMPv6(pkt *stack.PacketBuffer) bool {
	hdr, ok := pkt.Data().PullUp(header.ICMPv6MinimumSize)
	if !ok {
		return false
	}

	h := header.ICMPv6(hdr)
	switch h.Type() {
	case header.ICMPv6RouterSolicit,
		header.ICMPv6RouterAdvert,
		header.ICMPv6NeighborSolicit,
		header.ICMPv6NeighborAdvert,
		header.ICMPv6RedirectMsg:
		size := pkt.Data().Size()
		if _, ok := pkt.TransportHeader().Consume(size); !ok {
			panic(fmt.Sprintf("expected to consume the full data of size = %d bytes into transport header", size))
		}
	case header.ICMPv6MulticastListenerQuery,
		header.ICMPv6MulticastListenerReport,
		header.ICMPv6MulticastListenerDone:
		size := header.ICMPv6HeaderSize + header.MLDMinimumSize
		if _, ok := pkt.TransportHeader().Consume(size); !ok {
			return false
		}
	case header.ICMPv6DstUnreachable,
		header.ICMPv6PacketTooBig,
		header.ICMPv6TimeExceeded,
		header.ICMPv6ParamProblem,
		header.ICMPv6EchoRequest,
		header.ICMPv6EchoReply:
		fallthrough
	default:
		if _, ok := pkt.TransportHeader().Consume(header.ICMPv6MinimumSize); !ok {
			// Checked above if the packet buffer holds at least the minimum size for
			// an ICMPv6 packet.
			panic(fmt.Sprintf("expected to consume %d bytes", header.ICMPv6MinimumSize))
		}
	}
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	return true
}
