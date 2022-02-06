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

package header

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ICMPv6 represents an ICMPv6 header stored in a byte array.
type ICMPv6 []byte

const (
	// ICMPv6HeaderSize is the size of the ICMPv6 header. That is, the
	// sum of the size of the ICMPv6 Type, Code and Checksum fields, as
	// per RFC 4443 section 2.1. After the ICMPv6 header, the ICMPv6
	// message body begins.
	ICMPv6HeaderSize = 4

	// ICMPv6MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv6MinimumSize = 8

	// ICMPv6PayloadOffset is the offset of the payload in an
	// ICMP packet.
	ICMPv6PayloadOffset = 8

	// ICMPv6ProtocolNumber is the ICMP transport protocol number.
	ICMPv6ProtocolNumber tcpip.TransportProtocolNumber = 58

	// ICMPv6NeighborSolicitMinimumSize is the minimum size of a
	// neighbor solicitation packet.
	ICMPv6NeighborSolicitMinimumSize = ICMPv6HeaderSize + NDPNSMinimumSize

	// ICMPv6NeighborAdvertMinimumSize is the minimum size of a
	// neighbor advertisement packet.
	ICMPv6NeighborAdvertMinimumSize = ICMPv6HeaderSize + NDPNAMinimumSize

	// ICMPv6EchoMinimumSize is the minimum size of a valid echo packet.
	ICMPv6EchoMinimumSize = 8

	// ICMPv6ErrorHeaderSize is the size of an ICMP error packet header,
	// as per RFC 4443, Apendix A, item 4 and the errata.
	//   ... all ICMP error messages shall have exactly
	//   32 bits of type-specific data, so that receivers can reliably find
	//   the embedded invoking packet even when they don't recognize the
	//   ICMP message Type.
	ICMPv6ErrorHeaderSize = 8

	// ICMPv6DstUnreachableMinimumSize is the minimum size of a valid ICMP
	// destination unreachable packet.
	ICMPv6DstUnreachableMinimumSize = ICMPv6MinimumSize

	// ICMPv6PacketTooBigMinimumSize is the minimum size of a valid ICMP
	// packet-too-big packet.
	ICMPv6PacketTooBigMinimumSize = ICMPv6MinimumSize

	// ICMPv6ChecksumOffset is the offset of the checksum field
	// in an ICMPv6 message.
	ICMPv6ChecksumOffset = 2

	// icmpv6PointerOffset is the offset of the pointer
	// in an ICMPv6 Parameter problem message.
	icmpv6PointerOffset = 4

	// icmpv6MTUOffset is the offset of the MTU field in an ICMPv6
	// PacketTooBig message.
	icmpv6MTUOffset = 4

	// icmpv6IdentOffset is the offset of the ident field
	// in a ICMPv6 Echo Request/Reply message.
	icmpv6IdentOffset = 4

	// icmpv6SequenceOffset is the offset of the sequence field
	// in a ICMPv6 Echo Request/Reply message.
	icmpv6SequenceOffset = 6

	// NDPHopLimit is the expected IP hop limit value of 255 for received
	// NDP packets, as per RFC 4861 sections 4.1 - 4.5, 6.1.1, 6.1.2, 7.1.1,
	// 7.1.2 and 8.1. If the hop limit value is not 255, nodes MUST silently
	// drop the NDP packet. All outgoing NDP packets must use this value for
	// its IP hop limit field.
	NDPHopLimit = 255
)

// ICMPv6Type is the ICMP type field described in RFC 4443.
type ICMPv6Type byte

// Values for use in the Type field of ICMPv6 packet from RFC 4433.
const (
	ICMPv6DstUnreachable ICMPv6Type = 1
	ICMPv6PacketTooBig   ICMPv6Type = 2
	ICMPv6TimeExceeded   ICMPv6Type = 3
	ICMPv6ParamProblem   ICMPv6Type = 4
	ICMPv6EchoRequest    ICMPv6Type = 128
	ICMPv6EchoReply      ICMPv6Type = 129

	// Neighbor Discovery Protocol (NDP) messages, see RFC 4861.

	ICMPv6RouterSolicit   ICMPv6Type = 133
	ICMPv6RouterAdvert    ICMPv6Type = 134
	ICMPv6NeighborSolicit ICMPv6Type = 135
	ICMPv6NeighborAdvert  ICMPv6Type = 136
	ICMPv6RedirectMsg     ICMPv6Type = 137

	// Multicast Listener Discovery (MLD) messages, see RFC 2710.

	ICMPv6MulticastListenerQuery  ICMPv6Type = 130
	ICMPv6MulticastListenerReport ICMPv6Type = 131
	ICMPv6MulticastListenerDone   ICMPv6Type = 132
)

// IsErrorType returns true if the receiver is an ICMP error type.
func (typ ICMPv6Type) IsErrorType() bool {
	// Per RFC 4443 section 2.1:
	//   ICMPv6 messages are grouped into two classes: error messages and
	//   informational messages.  Error messages are identified as such by a
	//   zero in the high-order bit of their message Type field values.  Thus,
	//   error messages have message types from 0 to 127; informational
	//   messages have message types from 128 to 255.
	return typ&0x80 == 0
}

// ICMPv6Code is the ICMP Code field described in RFC 4443.
type ICMPv6Code byte

// ICMP codes used with Destination Unreachable (Type 1). As per RFC 4443
// section 3.1.
const (
	ICMPv6NetworkUnreachable ICMPv6Code = 0
	ICMPv6Prohibited         ICMPv6Code = 1
	ICMPv6BeyondScope        ICMPv6Code = 2
	ICMPv6AddressUnreachable ICMPv6Code = 3
	ICMPv6PortUnreachable    ICMPv6Code = 4
	ICMPv6Policy             ICMPv6Code = 5
	ICMPv6RejectRoute        ICMPv6Code = 6
)

// ICMP codes used with Time Exceeded (Type 3). As per RFC 4443 section 3.3.
const (
	ICMPv6HopLimitExceeded  ICMPv6Code = 0
	ICMPv6ReassemblyTimeout ICMPv6Code = 1
)

// ICMP codes used with Parameter Problem (Type 4). As per RFC 4443 section 3.4.
const (
	// ICMPv6ErroneousHeader indicates an erroneous header field was encountered.
	ICMPv6ErroneousHeader ICMPv6Code = 0

	// ICMPv6UnknownHeader indicates an unrecognized Next Header type encountered.
	ICMPv6UnknownHeader ICMPv6Code = 1

	// ICMPv6UnknownOption indicates an unrecognized IPv6 option was encountered.
	ICMPv6UnknownOption ICMPv6Code = 2
)

// ICMPv6UnusedCode is the code value used with ICMPv6 messages which don't use
// the code field. (Types not mentioned above.)
const ICMPv6UnusedCode ICMPv6Code = 0

// Type is the ICMP type field.
func (b ICMPv6) Type() ICMPv6Type { return ICMPv6Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv6) SetType(t ICMPv6Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv6) Code() ICMPv6Code { return ICMPv6Code(b[1]) }

// SetCode sets the ICMP code field.
func (b ICMPv6) SetCode(c ICMPv6Code) { b[1] = byte(c) }

// TypeSpecific returns the type specific data field.
func (b ICMPv6) TypeSpecific() uint32 {
	return binary.BigEndian.Uint32(b[icmpv6PointerOffset:])
}

// SetTypeSpecific sets the type specific data field.
func (b ICMPv6) SetTypeSpecific(val uint32) {
	binary.BigEndian.PutUint32(b[icmpv6PointerOffset:], val)
}

// Checksum is the ICMP checksum field.
func (b ICMPv6) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[ICMPv6ChecksumOffset:])
}

// SetChecksum sets the ICMP checksum field.
func (b ICMPv6) SetChecksum(checksum uint16) {
	PutChecksum(b[ICMPv6ChecksumOffset:], checksum)
}

// SourcePort implements Transport.SourcePort.
func (ICMPv6) SourcePort() uint16 {
	return 0
}

// DestinationPort implements Transport.DestinationPort.
func (ICMPv6) DestinationPort() uint16 {
	return 0
}

// SetSourcePort implements Transport.SetSourcePort.
func (ICMPv6) SetSourcePort(uint16) {
}

// SetDestinationPort implements Transport.SetDestinationPort.
func (ICMPv6) SetDestinationPort(uint16) {
}

// MTU retrieves the MTU field from an ICMPv6 message.
func (b ICMPv6) MTU() uint32 {
	return binary.BigEndian.Uint32(b[icmpv6MTUOffset:])
}

// SetMTU sets the MTU field from an ICMPv6 message.
func (b ICMPv6) SetMTU(mtu uint32) {
	binary.BigEndian.PutUint32(b[icmpv6MTUOffset:], mtu)
}

// Ident retrieves the Ident field from an ICMPv6 message.
func (b ICMPv6) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6IdentOffset:])
}

// SetIdent sets the Ident field from an ICMPv6 message.
func (b ICMPv6) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv6IdentOffset:], ident)
}

// SetIdentWithChecksumUpdate sets the Ident field and updates the checksum.
func (b ICMPv6) SetIdentWithChecksumUpdate(new uint16) {
	old := b.Ident()
	b.SetIdent(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

// Sequence retrieves the Sequence field from an ICMPv6 message.
func (b ICMPv6) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv6SequenceOffset:])
}

// SetSequence sets the Sequence field from an ICMPv6 message.
func (b ICMPv6) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv6SequenceOffset:], sequence)
}

// MessageBody returns the message body as defined by RFC 4443 section 2.1; the
// portion of the ICMPv6 buffer after the first ICMPv6HeaderSize bytes.
func (b ICMPv6) MessageBody() []byte {
	return b[ICMPv6HeaderSize:]
}

// Payload implements Transport.Payload.
func (b ICMPv6) Payload() []byte {
	return b[ICMPv6PayloadOffset:]
}

// ICMPv6ChecksumParams contains parameters to calculate ICMPv6 checksum.
type ICMPv6ChecksumParams struct {
	Header      ICMPv6
	Src         tcpip.Address
	Dst         tcpip.Address
	PayloadCsum uint16
	PayloadLen  int
}

// ICMPv6Checksum calculates the ICMP checksum over the provided ICMPv6 header,
// IPv6 src/dst addresses and the payload.
func ICMPv6Checksum(params ICMPv6ChecksumParams) uint16 {
	h := params.Header

	xsum := PseudoHeaderChecksum(ICMPv6ProtocolNumber, params.Src, params.Dst, uint16(len(h)+params.PayloadLen))
	xsum = ChecksumCombine(xsum, params.PayloadCsum)

	// h[2:4] is the checksum itself, skip it to avoid checksumming the checksum.
	xsum = Checksum(h[:2], xsum)
	xsum = Checksum(h[4:], xsum)

	return ^xsum
}

// UpdateChecksumPseudoHeaderAddress updates the checksum to reflect an
// updated address in the pseudo header.
func (b ICMPv6) UpdateChecksumPseudoHeaderAddress(old, new tcpip.Address) {
	b.SetChecksum(^checksumUpdate2ByteAlignedAddress(^b.Checksum(), old, new))
}
