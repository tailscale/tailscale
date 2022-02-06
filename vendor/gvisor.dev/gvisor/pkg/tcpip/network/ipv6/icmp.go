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

package ipv6

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// icmpv6DestinationUnreachableSockError is a general ICMPv6 Destination
// Unreachable error.
//
// +stateify savable
type icmpv6DestinationUnreachableSockError struct{}

// Origin implements tcpip.SockErrorCause.
func (*icmpv6DestinationUnreachableSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP6
}

// Type implements tcpip.SockErrorCause.
func (*icmpv6DestinationUnreachableSockError) Type() uint8 {
	return uint8(header.ICMPv6DstUnreachable)
}

// Info implements tcpip.SockErrorCause.
func (*icmpv6DestinationUnreachableSockError) Info() uint32 {
	return 0
}

var _ stack.TransportError = (*icmpv6DestinationNetworkUnreachableSockError)(nil)

// icmpv6DestinationNetworkUnreachableSockError is an ICMPv6 Destination Network
// Unreachable error.
//
// It indicates that the destination network is unreachable.
//
// +stateify savable
type icmpv6DestinationNetworkUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

// Code implements tcpip.SockErrorCause.
func (*icmpv6DestinationNetworkUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6NetworkUnreachable)
}

// Kind implements stack.TransportError.
func (*icmpv6DestinationNetworkUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationNetworkUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6DestinationPortUnreachableSockError)(nil)

// icmpv6DestinationPortUnreachableSockError is an ICMPv6 Destination Port
// Unreachable error.
//
// It indicates that a packet reached the destination host, but the transport
// protocol was not active on the destination port.
//
// +stateify savable
type icmpv6DestinationPortUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

// Code implements tcpip.SockErrorCause.
func (*icmpv6DestinationPortUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6PortUnreachable)
}

// Kind implements stack.TransportError.
func (*icmpv6DestinationPortUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationPortUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6DestinationAddressUnreachableSockError)(nil)

// icmpv6DestinationAddressUnreachableSockError is an ICMPv6 Destination Address
// Unreachable error.
//
// It indicates that a packet was not able to reach the destination.
//
// +stateify savable
type icmpv6DestinationAddressUnreachableSockError struct {
	icmpv6DestinationUnreachableSockError
}

// Code implements tcpip.SockErrorCause.
func (*icmpv6DestinationAddressUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv6AddressUnreachable)
}

// Kind implements stack.TransportError.
func (*icmpv6DestinationAddressUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationHostUnreachableTransportError
}

var _ stack.TransportError = (*icmpv6PacketTooBigSockError)(nil)

// icmpv6PacketTooBigSockError is an ICMPv6 Packet Too Big error.
//
// It indicates that a link exists on the path to the destination with an MTU
// that is too small to carry the packet.
//
// +stateify savable
type icmpv6PacketTooBigSockError struct {
	mtu uint32
}

// Origin implements tcpip.SockErrorCause.
func (*icmpv6PacketTooBigSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP6
}

// Type implements tcpip.SockErrorCause.
func (*icmpv6PacketTooBigSockError) Type() uint8 {
	return uint8(header.ICMPv6PacketTooBig)
}

// Code implements tcpip.SockErrorCause.
func (*icmpv6PacketTooBigSockError) Code() uint8 {
	return uint8(header.ICMPv6UnusedCode)
}

// Info implements tcpip.SockErrorCause.
func (e *icmpv6PacketTooBigSockError) Info() uint32 {
	return e.mtu
}

// Kind implements stack.TransportError.
func (*icmpv6PacketTooBigSockError) Kind() stack.TransportErrorKind {
	return stack.PacketTooBigTransportError
}

func (e *endpoint) checkLocalAddress(addr tcpip.Address) bool {
	if e.nic.Spoofing() {
		return true
	}

	if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
		return true
	}
	return false
}

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return
	}
	hdr := header.IPv6(h)

	// We don't use IsValid() here because ICMP only requires that up to
	// 1280 bytes of the original packet be included. So it's likely that it
	// is truncated, which would cause IsValid to return false.
	//
	// Drop packet if it doesn't have the basic IPv6 header or if the
	// original source address doesn't match an address we own.
	srcAddr := hdr.SourceAddress()
	if !e.checkLocalAddress(srcAddr) {
		return
	}

	// Keep needed information before trimming header.
	p := hdr.TransportProtocol()
	dstAddr := hdr.DestinationAddress()

	// Skip the IP header, then handle the fragmentation header if there
	// is one.
	if _, ok := pkt.Data().Consume(header.IPv6MinimumSize); !ok {
		panic("could not consume IPv6MinimumSize bytes")
	}
	if p == header.IPv6FragmentHeader {
		f, ok := pkt.Data().PullUp(header.IPv6FragmentHeaderSize)
		if !ok {
			return
		}
		fragHdr := header.IPv6Fragment(f)
		if !fragHdr.IsValid() || fragHdr.FragmentOffset() != 0 {
			// We can't handle fragments that aren't at offset 0
			// because they don't have the transport headers.
			return
		}
		p = fragHdr.TransportProtocol()

		// Skip fragmentation header and find out the actual protocol
		// number.
		if _, ok := pkt.Data().Consume(header.IPv6FragmentHeaderSize); !ok {
			panic("could not consume IPv6FragmentHeaderSize bytes")
		}
	}

	e.dispatcher.DeliverTransportError(srcAddr, dstAddr, ProtocolNumber, p, transErr, pkt)
}

// getLinkAddrOption searches NDP options for a given link address option using
// the provided getAddr function as a filter. Returns the link address if
// found; otherwise, returns the zero link address value. Also returns true if
// the options are valid as per the wire format, false otherwise.
func getLinkAddrOption(it header.NDPOptionIterator, getAddr func(header.NDPOption) tcpip.LinkAddress) (tcpip.LinkAddress, bool) {
	var linkAddr tcpip.LinkAddress
	for {
		opt, done, err := it.Next()
		if err != nil {
			return "", false
		}
		if done {
			break
		}
		if addr := getAddr(opt); len(addr) != 0 {
			// No RFCs define what to do when an NDP message has multiple Link-Layer
			// Address options. Since no interface can have multiple link-layer
			// addresses, we consider such messages invalid.
			if len(linkAddr) != 0 {
				return "", false
			}
			linkAddr = addr
		}
	}
	return linkAddr, true
}

// getSourceLinkAddr searches NDP options for the source link address option.
// Returns the link address if found; otherwise, returns the zero link address
// value. Also returns true if the options are valid as per the wire format,
// false otherwise.
func getSourceLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if src, ok := opt.(header.NDPSourceLinkLayerAddressOption); ok {
			return src.EthernetAddress()
		}
		return ""
	})
}

// getTargetLinkAddr searches NDP options for the target link address option.
// Returns the link address if found; otherwise, returns the zero link address
// value. Also returns true if the options are valid as per the wire format,
// false otherwise.
func getTargetLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if dst, ok := opt.(header.NDPTargetLinkLayerAddressOption); ok {
			return dst.EthernetAddress()
		}
		return ""
	})
}

func isMLDValid(pkt *stack.PacketBuffer, iph header.IPv6, routerAlert *header.IPv6RouterAlertOption) bool {
	// As per RFC 2710 section 3:
	//   All MLD messages described in this document are sent with a link-local
	//   IPv6 Source Address, an IPv6 Hop Limit of 1, and an IPv6 Router Alert
	//   option in a Hop-by-Hop Options header.
	if routerAlert == nil || routerAlert.Value != header.IPv6RouterAlertMLD {
		return false
	}
	if pkt.TransportHeader().View().Size() < header.ICMPv6HeaderSize+header.MLDMinimumSize {
		return false
	}
	if iph.HopLimit() != header.MLDHopLimit {
		return false
	}
	if !header.IsV6LinkLocalUnicastAddress(iph.SourceAddress()) {
		return false
	}
	return true
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer, hasFragmentHeader bool, routerAlert *header.IPv6RouterAlertOption) {
	sent := e.stats.icmp.packetsSent
	received := e.stats.icmp.packetsReceived
	h := header.ICMPv6(pkt.TransportHeader().View())
	if len(h) < header.ICMPv6MinimumSize {
		received.invalid.Increment()
		return
	}
	iph := header.IPv6(pkt.NetworkHeader().View())
	srcAddr := iph.SourceAddress()
	dstAddr := iph.DestinationAddress()

	// Validate ICMPv6 checksum before processing the packet.
	payload := pkt.Data().AsRange()
	if got, want := h.Checksum(), header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      h,
		Src:         srcAddr,
		Dst:         dstAddr,
		PayloadCsum: payload.Checksum(),
		PayloadLen:  payload.Size(),
	}); got != want {
		received.invalid.Increment()
		return
	}

	isNDPValid := func() bool {
		// As per RFC 4861 sections 4.1 - 4.5, 6.1.1, 6.1.2, 7.1.1, 7.1.2 and
		// 8.1, nodes MUST silently drop NDP packets where the Hop Limit field
		// in the IPv6 header is not set to 255, or the ICMPv6 Code field is not
		// set to 0.
		//
		// As per RFC 6980 section 5, nodes MUST silently drop NDP messages if the
		// packet includes a fragmentation header.
		return !hasFragmentHeader && iph.HopLimit() == header.NDPHopLimit && h.Code() == 0
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch icmpType := h.Type(); icmpType {
	case header.ICMPv6PacketTooBig:
		received.packetTooBig.Increment()
		networkMTU, err := calculateNetworkMTU(h.MTU(), header.IPv6MinimumSize)
		if err != nil {
			networkMTU = 0
		}
		e.handleControl(&icmpv6PacketTooBigSockError{mtu: networkMTU}, pkt)

	case header.ICMPv6DstUnreachable:
		received.dstUnreachable.Increment()
		switch h.Code() {
		case header.ICMPv6NetworkUnreachable:
			e.handleControl(&icmpv6DestinationNetworkUnreachableSockError{}, pkt)
		case header.ICMPv6PortUnreachable:
			e.handleControl(&icmpv6DestinationPortUnreachableSockError{}, pkt)
		}
	case header.ICMPv6NeighborSolicit:
		received.neighborSolicit.Increment()
		if !isNDPValid() || len(h) < header.ICMPv6NeighborSolicitMinimumSize {
			received.invalid.Increment()
			return
		}

		ns := header.NDPNeighborSolicit(h.MessageBody())
		targetAddr := ns.TargetAddress()

		// As per RFC 4861 section 4.3, the Target Address MUST NOT be a multicast
		// address.
		if header.IsV6MulticastAddress(targetAddr) {
			received.invalid.Increment()
			return
		}

		var it header.NDPOptionIterator
		{
			var err error
			it, err = ns.Options().Iter(false /* check */)
			if err != nil {
				// Options are not valid as per the wire format, silently drop the
				// packet.
				received.invalid.Increment()
				return
			}
		}

		if e.hasTentativeAddr(targetAddr) {
			// If the target address is tentative and the source of the packet is a
			// unicast (specified) address, then the source of the packet is
			// attempting to perform address resolution on the target. In this case,
			// the solicitation is silently ignored, as per RFC 4862 section 5.4.3.
			//
			// If the target address is tentative and the source of the packet is the
			// unspecified address (::), then we know another node is also performing
			// DAD for the same address (since the target address is tentative for us,
			// we know we are also performing DAD on it). In this case we let the
			// stack know so it can handle such a scenario and do nothing further with
			// the NS.
			if srcAddr == header.IPv6Any {
				var nonce []byte
				for {
					opt, done, err := it.Next()
					if err != nil {
						received.invalid.Increment()
						return
					}
					if done {
						break
					}
					if n, ok := opt.(header.NDPNonceOption); ok {
						nonce = n.Nonce()
						break
					}
				}

				// Since this is a DAD message we know the sender does not actually hold
				// the target address so there is no "holder".
				var holderLinkAddress tcpip.LinkAddress

				// We would get an error if the address no longer exists or the address
				// is no longer tentative (DAD resolved between the call to
				// hasTentativeAddr and this point). Both of these are valid scenarios:
				//   1) An address may be removed at any time.
				//   2) As per RFC 4862 section 5.4, DAD is not a perfect:
				//       "Note that the method for detecting duplicates
				//        is not completely reliable, and it is possible that duplicate
				//        addresses will still exist"
				//
				// TODO(gvisor.dev/issue/4046): Handle the scenario when a duplicate
				// address is detected for an assigned address.
				switch err := e.dupTentativeAddrDetected(targetAddr, holderLinkAddress, nonce); err.(type) {
				case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				default:
					panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
				}
			}

			// Do not handle neighbor solicitations targeted to an address that is
			// tentative on the NIC any further.
			return
		}

		// At this point we know that the target address is not tentative on the NIC
		// so the packet is processed as defined in RFC 4861, as per RFC 4862
		// section 5.4.3.

		// Is the NS targeting us?
		if !e.checkLocalAddress(targetAddr) {
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		// As per RFC 4861 section 4.3, the Source Link-Layer Address Option MUST
		// NOT be included when the source IP address is the unspecified address.
		// Otherwise, on link layers that have addresses this option MUST be
		// included in multicast solicitations and SHOULD be included in unicast
		// solicitations.
		unspecifiedSource := srcAddr == header.IPv6Any
		if len(sourceLinkAddr) == 0 {
			if header.IsV6MulticastAddress(dstAddr) && !unspecifiedSource {
				received.invalid.Increment()
				return
			}
		} else if unspecifiedSource {
			received.invalid.Increment()
			return
		} else {
			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, srcAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			// The stack may support ICMPv6 but the NIC may not need link resolution.
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

		// As per RFC 4861 section 7.1.1:
		//   A node MUST silently discard any received Neighbor Solicitation
		//   messages that do not satisfy all of the following validity checks:
		//    ...
		//    - If the IP source address is the unspecified address, the IP
		//      destination address is a solicited-node multicast address.
		if unspecifiedSource && !header.IsSolicitedNodeAddr(dstAddr) {
			received.invalid.Increment()
			return
		}

		// As per RFC 4861 section 7.2.4:
		//
		//   If the source of the solicitation is the unspecified address, the node
		//   MUST [...] and multicast the advertisement to the all-nodes address.
		//
		remoteAddr := srcAddr
		if unspecifiedSource {
			remoteAddr = header.IPv6AllNodesMulticastAddress
		}

		// Even if we were able to receive a packet from some remote, we may not
		// have a route to it - the remote may be blocked via routing rules. We must
		// always consult our routing table and find a route to the remote before
		// sending any packet.
		r, err := e.protocol.stack.FindRoute(e.nic.ID(), targetAddr, remoteAddr, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// If the NS has a source link-layer option, resolve the route immediately
		// to avoid querying the neighbor table when the neighbor entry was updated
		// as probing the neighbor table for a link address will transition the
		// entry's state from stale to delay.
		//
		// Note, if the source link address is unspecified and this is a unicast
		// solicitation, we may need to perform neighbor discovery to send the
		// neighbor advertisement response. This is expected as per RFC 4861 section
		// 7.2.4:
		//
		//   Because unicast Neighbor Solicitations are not required to include a
		//   Source Link-Layer Address, it is possible that a node sending a
		//   solicited Neighbor Advertisement does not have a corresponding link-
		//   layer address for its neighbor in its Neighbor Cache. In such
		//   situations, a node will first have to use Neighbor Discovery to
		//   determine the link-layer address of its neighbor (i.e., send out a
		//   multicast Neighbor Solicitation).
		//
		if len(sourceLinkAddr) != 0 {
			r.ResolveWith(sourceLinkAddr)
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(e.nic.LinkAddress()),
		}
		neighborAdvertSize := header.ICMPv6NeighborAdvertMinimumSize + optsSerializer.Length()
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + neighborAdvertSize,
		})
		defer pkt.DecRef()
		pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
		packet := header.ICMPv6(pkt.TransportHeader().Push(neighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.MessageBody())

		// As per RFC 4861 section 7.2.4:
		//
		//   If the source of the solicitation is the unspecified address, the node
		//   MUST set the Solicited flag to zero and [..]. Otherwise, the node MUST
		//   set the Solicited flag to one and [..].
		//
		na.SetSolicitedFlag(!unspecifiedSource)
		na.SetOverrideFlag(true)
		na.SetTargetAddress(targetAddr)
		na.Options().Serialize(optsSerializer)
		packet.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: packet,
			Src:    r.LocalAddress(),
			Dst:    r.RemoteAddress(),
		}))

		// RFC 4861 Neighbor Discovery for IP version 6 (IPv6)
		//
		// 7.1.2. Validation of Neighbor Advertisements
		//
		// The IP Hop Limit field has a value of 255, i.e., the packet
		// could not possibly have been forwarded by a router.
		if err := r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, pkt); err != nil {
			sent.dropped.Increment()
			return
		}
		sent.neighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.neighborAdvert.Increment()
		if !isNDPValid() || len(h) < header.ICMPv6NeighborAdvertMinimumSize {
			received.invalid.Increment()
			return
		}

		na := header.NDPNeighborAdvert(h.MessageBody())

		it, err := na.Options().Iter(false /* check */)
		if err != nil {
			// If we have a malformed NDP NA option, drop the packet.
			received.invalid.Increment()
			return
		}

		targetLinkAddr, ok := getTargetLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		targetAddr := na.TargetAddress()

		e.dad.mu.Lock()
		e.dad.mu.dad.StopLocked(targetAddr, &stack.DADDupAddrDetected{HolderLinkAddress: targetLinkAddr})
		e.dad.mu.Unlock()

		if e.hasTentativeAddr(targetAddr) {
			// We only send a nonce value in DAD messages to check for loopedback
			// messages so we use the empty nonce value here.
			var nonce []byte

			// We just got an NA from a node that owns an address we are performing
			// DAD on, implying the address is not unique. In this case we let the
			// stack know so it can handle such a scenario and do nothing furthur with
			// the NDP NA.
			//
			// We would get an error if the address no longer exists or the address
			// is no longer tentative (DAD resolved between the call to
			// hasTentativeAddr and this point). Both of these are valid scenarios:
			//   1) An address may be removed at any time.
			//   2) As per RFC 4862 section 5.4, DAD is not a perfect:
			//       "Note that the method for detecting duplicates
			//        is not completely reliable, and it is possible that duplicate
			//        addresses will still exist"
			//
			// TODO(gvisor.dev/issue/4046): Handle the scenario when a duplicate
			// address is detected for an assigned address.
			switch err := e.dupTentativeAddrDetected(targetAddr, targetLinkAddr, nonce); err.(type) {
			case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				return
			default:
				panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
			}
		}

		// At this point we know that the target address is not tentative on the
		// NIC. However, the target address may still be assigned to the NIC but not
		// tentative (it could be permanent). Such a scenario is beyond the scope of
		// RFC 4862. As such, we simply ignore such a scenario for now and proceed
		// as normal.
		//
		// TODO(b/143147598): Handle the scenario described above. Also inform the
		// netstack integration that a duplicate address was detected outside of
		// DAD.

		// As per RFC 4861 section 7.1.2:
		//   A node MUST silently discard any received Neighbor Advertisement
		//   messages that do not satisfy all of the following validity checks:
		//    ...
		//    - If the IP Destination Address is a multicast address the
		// 	    Solicited flag is zero.
		if header.IsV6MulticastAddress(dstAddr) && na.SolicitedFlag() {
			received.invalid.Increment()
			return
		}

		// If the NA message has the target link layer option, update the link
		// address cache with the link address for the target of the message.
		switch err := e.nic.HandleNeighborConfirmation(ProtocolNumber, targetAddr, targetLinkAddr, stack.ReachabilityConfirmationFlags{
			Solicited: na.SolicitedFlag(),
			Override:  na.OverrideFlag(),
			IsRouter:  na.RouterFlag(),
		}); err.(type) {
		case nil:
		case *tcpip.ErrNotSupported:
		// The stack may support ICMPv6 but the NIC may not need link resolution.
		default:
			panic(fmt.Sprintf("unexpected error when informing NIC of neighbor confirmation message: %s", err))
		}

	case header.ICMPv6EchoRequest:
		received.echoRequest.Increment()
		// As per RFC 4291 section 2.7, multicast addresses must not be used as
		// source addresses in IPv6 packets.
		localAddr := dstAddr
		if header.IsV6MulticastAddress(dstAddr) {
			localAddr = ""
		}

		r, err := e.protocol.stack.FindRoute(e.nic.ID(), localAddr, srcAddr, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		if !e.protocol.allowICMPReply(header.ICMPv6EchoReply) {
			sent.rateLimited.Increment()
			return
		}

		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
			Data:               pkt.Data().ExtractVV(),
		})
		defer replyPkt.DecRef()
		icmp := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
		replyPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
		copy(icmp, h)
		icmp.SetType(header.ICMPv6EchoReply)
		dataRange := replyPkt.Data().AsRange()
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmp,
			Src:         r.LocalAddress(),
			Dst:         r.RemoteAddress(),
			PayloadCsum: dataRange.Checksum(),
			PayloadLen:  dataRange.Size(),
		}))
		if err := r.WritePacket(stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      r.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		}, replyPkt); err != nil {
			sent.dropped.Increment()
			return
		}
		sent.echoReply.Increment()

	case header.ICMPv6EchoReply:
		received.echoReply.Increment()
		if len(h) < header.ICMPv6EchoMinimumSize {
			received.invalid.Increment()
			return
		}
		e.dispatcher.DeliverTransportPacket(header.ICMPv6ProtocolNumber, pkt)

	case header.ICMPv6TimeExceeded:
		received.timeExceeded.Increment()

	case header.ICMPv6ParamProblem:
		received.paramProblem.Increment()

	case header.ICMPv6RouterSolicit:
		received.routerSolicit.Increment()

		//
		// Validate the RS as per RFC 4861 section 6.1.1.
		//

		// Is the NDP payload of sufficient size to hold a Router Solictation?
		if !isNDPValid() || len(h)-header.ICMPv6HeaderSize < header.NDPRSMinimumSize {
			received.invalid.Increment()
			return
		}

		if !e.Forwarding() {
			received.routerOnlyPacketsDroppedByHost.Increment()
			return
		}

		rs := header.NDPRouterSolicit(h.MessageBody())
		it, err := rs.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		// If the RS message has the source link layer option, update the link
		// address cache with the link address for the source of the message.
		if len(sourceLinkAddr) != 0 {
			// As per RFC 4861 section 4.1, the Source Link-Layer Address Option MUST
			// NOT be included when the source IP address is the unspecified address.
			// Otherwise, it SHOULD be included on link layers that have addresses.
			if srcAddr == header.IPv6Any {
				received.invalid.Increment()
				return
			}

			// A RS with a specified source IP address modifies the neighbor table
			// in the same way a regular probe would.
			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, srcAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			// The stack may support ICMPv6 but the NIC may not need link resolution.
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

	case header.ICMPv6RouterAdvert:
		received.routerAdvert.Increment()

		//
		// Validate the RA as per RFC 4861 section 6.1.2.
		//

		// Is the NDP payload of sufficient size to hold a Router Advertisement?
		if !isNDPValid() || len(h)-header.ICMPv6HeaderSize < header.NDPRAMinimumSize {
			received.invalid.Increment()
			return
		}

		routerAddr := srcAddr

		// Is the IP Source Address a link-local address?
		if !header.IsV6LinkLocalUnicastAddress(routerAddr) {
			// ...No, silently drop the packet.
			received.invalid.Increment()
			return
		}

		ra := header.NDPRouterAdvert(h.MessageBody())
		it, err := ra.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		//
		// At this point, we have a valid Router Advertisement, as far
		// as RFC 4861 section 6.1.2 is concerned.
		//

		// If the RA has the source link layer option, update the link address
		// cache with the link address for the advertised router.
		if len(sourceLinkAddr) != 0 {
			switch err := e.nic.HandleNeighborProbe(ProtocolNumber, routerAddr, sourceLinkAddr); err.(type) {
			case nil:
			case *tcpip.ErrNotSupported:
			// The stack may support ICMPv6 but the NIC may not need link resolution.
			default:
				panic(fmt.Sprintf("unexpected error when informing NIC of neighbor probe message: %s", err))
			}
		}

		e.mu.Lock()
		e.mu.ndp.handleRA(routerAddr, ra)
		e.mu.Unlock()

	case header.ICMPv6RedirectMsg:
		// TODO(gvisor.dev/issue/2285): Call `e.nud.HandleProbe` after validating
		// this redirect message, as per RFC 4871 section 7.3.3:
		//
		//    "A Neighbor Cache entry enters the STALE state when created as a
		//    result of receiving packets other than solicited Neighbor
		//    Advertisements (i.e., Router Solicitations, Router Advertisements,
		//    Redirects, and Neighbor Solicitations).  These packets contain the
		//    link-layer address of either the sender or, in the case of Redirect,
		//    the redirection target.  However, receipt of these link-layer
		//    addresses does not confirm reachability of the forward-direction path
		//    to that node.  Placing a newly created Neighbor Cache entry for which
		//    the link-layer address is known in the STALE state provides assurance
		//    that path failures are detected quickly. In addition, should a cached
		//    link-layer address be modified due to receiving one of the above
		//    messages, the state SHOULD also be set to STALE to provide prompt
		//    verification that the path to the new link-layer address is working."
		received.redirectMsg.Increment()
		if !isNDPValid() {
			received.invalid.Increment()
			return
		}

	case header.ICMPv6MulticastListenerQuery, header.ICMPv6MulticastListenerReport, header.ICMPv6MulticastListenerDone:
		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			received.multicastListenerQuery.Increment()
		case header.ICMPv6MulticastListenerReport:
			received.multicastListenerReport.Increment()
		case header.ICMPv6MulticastListenerDone:
			received.multicastListenerDone.Increment()
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

		if !isMLDValid(pkt, iph, routerAlert) {
			received.invalid.Increment()
			return
		}

		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			e.mu.Lock()
			e.mu.mld.handleMulticastListenerQuery(header.MLD(h.MessageBody()))
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerReport:
			e.mu.Lock()
			e.mu.mld.handleMulticastListenerReport(header.MLD(h.MessageBody()))
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerDone:
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

	default:
		received.unrecognized.Increment()
	}
}

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*endpoint) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (e *endpoint) LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	remoteAddr := targetAddr
	if len(remoteLinkAddr) == 0 {
		remoteAddr = header.SolicitedNodeAddr(targetAddr)
		remoteLinkAddr = header.EthernetAddressFromMulticastIPv6Address(remoteAddr)
	}

	if len(localAddr) == 0 {
		// Find an address that we can use as our source address.
		addressEndpoint := e.AcquireOutgoingPrimaryAddress(remoteAddr, false /* allowExpired */)
		if addressEndpoint == nil {
			return &tcpip.ErrNetworkUnreachable{}
		}

		localAddr = addressEndpoint.AddressWithPrefix().Address
		addressEndpoint.DecRef()
	} else if !e.checkLocalAddress(localAddr) {
		// The provided local address is not assigned to us.
		return &tcpip.ErrBadLocalAddress{}
	}

	return e.sendNDPNS(localAddr, remoteAddr, targetAddr, remoteLinkAddr, header.NDPOptionsSerializer{
		header.NDPSourceLinkLayerAddressOption(e.nic.LinkAddress()),
	})
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*endpoint) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}

// ======= ICMP Error packet generation =========

// icmpReason is a marker interface for IPv6 specific ICMP errors.
type icmpReason interface {
	isICMPReason()
	// respondToMulticast indicates whether this error falls under the exception
	// outlined by RFC 4443 section 2.4 point e.3 exception 2:
	//
	//   (e.3) A packet destined to an IPv6 multicast address. (There are two
	//   exceptions to this rule: (1) the Packet Too Big Message (Section 3.2) to
	//   allow Path MTU discovery to work for IPv6 multicast, and (2) the Parameter
	//   Problem Message, Code 2 (Section 3.4) reporting an unrecognized IPv6
	//   option (see Section 4.2 of [IPv6]) that has the Option Type highest-
	//   order two bits set to 10).
	respondsToMulticast() bool
}

// icmpReasonParameterProblem is an error during processing of extension headers
// or the fixed header defined in RFC 4443 section 3.4.
type icmpReasonParameterProblem struct {
	code header.ICMPv6Code

	// pointer is defined in the RFC 4443 setion 3.4 which reads:
	//
	//  Pointer         Identifies the octet offset within the invoking packet
	//                  where the error was detected.
	//
	//                  The pointer will point beyond the end of the ICMPv6
	//                  packet if the field in error is beyond what can fit
	//                  in the maximum size of an ICMPv6 error message.
	pointer uint32

	respondToMulticast bool
}

func (*icmpReasonParameterProblem) isICMPReason() {}

func (p *icmpReasonParameterProblem) respondsToMulticast() bool {
	return p.respondToMulticast
}

// icmpReasonAdministrativelyProhibited is an error where the destination is
// administratively prohibited.
type icmpReasonAdministrativelyProhibited struct{}

func (*icmpReasonAdministrativelyProhibited) isICMPReason() {}

func (*icmpReasonAdministrativelyProhibited) respondsToMulticast() bool {
	return false
}

// icmpReasonPortUnreachable is an error where the transport protocol has no
// listener and no alternative means to inform the sender.
type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}

func (*icmpReasonPortUnreachable) respondsToMulticast() bool {
	return false
}

// icmpReasonNetUnreachable is an error where no route can be found to the
// network of the final destination.
type icmpReasonNetUnreachable struct{}

func (*icmpReasonNetUnreachable) isICMPReason() {}

func (*icmpReasonNetUnreachable) respondsToMulticast() bool {
	return false
}

// icmpReasonHostUnreachable is an error in which the host specified in the
// internet destination field of the datagram is unreachable.
type icmpReasonHostUnreachable struct{}

func (*icmpReasonHostUnreachable) isICMPReason() {}

func (*icmpReasonHostUnreachable) respondsToMulticast() bool {
	return false
}

// icmpReasonFragmentationNeeded is an error where a packet is to big to be sent
// out through the outgoing MTU, as per RFC 4443 page 9, Packet Too Big Message.
type icmpReasonPacketTooBig struct{}

func (*icmpReasonPacketTooBig) isICMPReason() {}

func (*icmpReasonPacketTooBig) respondsToMulticast() bool {
	return true
}

// icmpReasonHopLimitExceeded is an error where a packet's hop limit exceeded in
// transit to its final destination, as per RFC 4443 section 3.3.
type icmpReasonHopLimitExceeded struct{}

func (*icmpReasonHopLimitExceeded) isICMPReason() {}

func (*icmpReasonHopLimitExceeded) respondsToMulticast() bool {
	return false
}

// icmpReasonReassemblyTimeout is an error where insufficient fragments are
// received to complete reassembly of a packet within a configured time after
// the reception of the first-arriving fragment of that packet.
type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}

func (*icmpReasonReassemblyTimeout) respondsToMulticast() bool {
	return false
}

// returnError takes an error descriptor and generates the appropriate ICMP
// error packet for IPv6 and sends it.
func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer, deliveredLocally bool) tcpip.Error {
	origIPHdr := header.IPv6(pkt.NetworkHeader().View())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	// Only send ICMP error if the address is not a multicast v6
	// address and the source is not the unspecified address.
	//
	// There are exceptions to this rule.
	// See: point e.3) RFC 4443 section-2.4
	//
	//	 (e) An ICMPv6 error message MUST NOT be originated as a result of
	//       receiving the following:
	//
	//       (e.1) An ICMPv6 error message.
	//
	//       (e.2) An ICMPv6 redirect message [IPv6-DISC].
	//
	//       (e.3) A packet destined to an IPv6 multicast address.  (There are
	//             two exceptions to this rule: (1) the Packet Too Big Message
	//             (Section 3.2) to allow Path MTU discovery to work for IPv6
	//             multicast, and (2) the Parameter Problem Message, Code 2
	//             (Section 3.4) reporting an unrecognized IPv6 option (see
	//             Section 4.2 of [IPv6]) that has the Option Type highest-
	//             order two bits set to 10).
	//
	allowResponseToMulticast := reason.respondsToMulticast()
	isOrigDstMulticast := header.IsV6MulticastAddress(origIPHdrDst)
	if (!allowResponseToMulticast && isOrigDstMulticast) || origIPHdrSrc == header.IPv6Any {
		return nil
	}

	// If the packet wasn't delivered locally, do not use the packet's destination
	// address as the response's source address as we should not own the
	// destination address of a packet we are forwarding.
	//
	// If the packet was originally destined to a multicast address, then do not
	// use the packet's destination address as the source for the response ICMP
	// packet as "multicast addresses must not be used as source addresses in IPv6
	// packets", as per RFC 4291 section 2.7.
	localAddr := origIPHdrDst
	if !deliveredLocally || isOrigDstMulticast {
		localAddr = ""
	}
	// Even if we were able to receive a packet from some remote, we may not have
	// a route to it - the remote may be blocked via routing rules. We must always
	// consult our routing table and find a route to the remote before sending any
	// packet.
	route, err := p.stack.FindRoute(pkt.NICID, localAddr, origIPHdrSrc, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer route.Release()

	p.mu.Lock()
	// We retrieve an endpoint using the newly constructed route's NICID rather
	// than the packet's NICID. The packet's NICID corresponds to the NIC on
	// which it arrived, which isn't necessarily the same as the NIC on which it
	// will be transmitted. On the other hand, the route's NIC *is* guaranteed
	// to be the NIC on which the packet will be transmitted.
	netEP, ok := p.mu.eps[route.NICID()]
	p.mu.Unlock()
	if !ok {
		return &tcpip.ErrNotConnected{}
	}

	if pkt.TransportProtocolNumber == header.ICMPv6ProtocolNumber {
		if typ := header.ICMPv6(pkt.TransportHeader().View()).Type(); typ.IsErrorType() || typ == header.ICMPv6RedirectMsg {
			return nil
		}
	}

	sent := netEP.stats.icmp.packetsSent
	icmpType, icmpCode, counter, typeSpecific := func() (header.ICMPv6Type, header.ICMPv6Code, tcpip.MultiCounterStat, uint32) {
		switch reason := reason.(type) {
		case *icmpReasonParameterProblem:
			return header.ICMPv6ParamProblem, reason.code, sent.paramProblem, reason.pointer
		case *icmpReasonAdministrativelyProhibited:
			return header.ICMPv6DstUnreachable, header.ICMPv6Prohibited, sent.dstUnreachable, 0
		case *icmpReasonPortUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, sent.dstUnreachable, 0
		case *icmpReasonNetUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6NetworkUnreachable, sent.dstUnreachable, 0
		case *icmpReasonHostUnreachable:
			return header.ICMPv6DstUnreachable, header.ICMPv6AddressUnreachable, sent.dstUnreachable, 0
		case *icmpReasonPacketTooBig:
			return header.ICMPv6PacketTooBig, header.ICMPv6UnusedCode, sent.packetTooBig, 0
		case *icmpReasonHopLimitExceeded:
			return header.ICMPv6TimeExceeded, header.ICMPv6HopLimitExceeded, sent.timeExceeded, 0
		case *icmpReasonReassemblyTimeout:
			return header.ICMPv6TimeExceeded, header.ICMPv6ReassemblyTimeout, sent.timeExceeded, 0
		default:
			panic(fmt.Sprintf("unsupported ICMP type %T", reason))
		}
	}()

	if !p.allowICMPReply(icmpType) {
		sent.rateLimited.Increment()
		return nil
	}

	network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()

	// As per RFC 4443 section 2.4
	//
	//    (c) Every ICMPv6 error message (type < 128) MUST include
	//    as much of the IPv6 offending (invoking) packet (the
	//    packet that caused the error) as possible without making
	//    the error message packet exceed the minimum IPv6 MTU
	//    [IPv6].
	mtu := int(route.MTU())
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil
	}
	payloadLen := network.Size() + transport.Size() + pkt.Data().Size()
	if payloadLen > available {
		payloadLen = available
	}
	payload := network.ToVectorisedView()
	payload.AppendView(transport)
	payload.Append(pkt.Data().ExtractVV())
	payload.CapLength(payloadLen)

	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6ErrorHeaderSize,
		Data:               payload,
	})
	defer newPkt.DecRef()
	newPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber

	icmpHdr := header.ICMPv6(newPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	icmpHdr.SetTypeSpecific(typeSpecific)

	dataRange := newPkt.Data().AsRange()
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         route.LocalAddress(),
		Dst:         route.RemoteAddress(),
		PayloadCsum: dataRange.Checksum(),
		PayloadLen:  dataRange.Size(),
	}))
	if err := route.WritePacket(
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		newPkt,
	); err != nil {
		sent.dropped.Increment()
		return err
	}
	counter.Increment()
	return nil
}

// OnReassemblyTimeout implements fragmentation.TimeoutHandler.
func (p *protocol) OnReassemblyTimeout(pkt *stack.PacketBuffer) {
	// OnReassemblyTimeout sends a Time Exceeded Message as per RFC 2460 Section
	// 4.5:
	//
	//   If the first fragment (i.e., the one with a Fragment Offset of zero) has
	//   been received, an ICMP Time Exceeded -- Fragment Reassembly Time Exceeded
	//   message should be sent to the source of that fragment.
	if pkt != nil {
		p.returnError(&icmpReasonReassemblyTimeout{}, pkt, true /* deliveredLocally */)
	}
}
