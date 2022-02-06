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

// ICMPv4 represents an ICMPv4 header stored in a byte array.
type ICMPv4 []byte

const (
	// ICMPv4PayloadOffset defines the start of ICMP payload.
	ICMPv4PayloadOffset = 8

	// ICMPv4MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv4MinimumSize = 8

	// ICMPv4MinimumErrorPayloadSize Is the smallest number of bytes of an
	// errant packet's transport layer that an ICMP error type packet should
	// attempt to send as per RFC 792 (see each type) and RFC 1122
	// section 3.2.2 which states:
	//      Every ICMP error message includes the Internet header and at
	//      least the first 8 data octets of the datagram that triggered
	//      the error; more than 8 octets MAY be sent; this header and data
	//      MUST be unchanged from the received datagram.
	//
	// RFC 792 shows:
	//   0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Type      |     Code      |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                             unused                            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Internet Header + 64 bits of Original Data Datagram      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	ICMPv4MinimumErrorPayloadSize = 8

	// ICMPv4ProtocolNumber is the ICMP transport protocol number.
	ICMPv4ProtocolNumber tcpip.TransportProtocolNumber = 1

	// icmpv4ChecksumOffset is the offset of the checksum field
	// in an ICMPv4 message.
	icmpv4ChecksumOffset = 2

	// icmpv4MTUOffset is the offset of the MTU field
	// in an ICMPv4FragmentationNeeded message.
	icmpv4MTUOffset = 6

	// icmpv4IdentOffset is the offset of the ident field
	// in an ICMPv4EchoRequest/Reply message.
	icmpv4IdentOffset = 4

	// icmpv4PointerOffset is the offset of the pointer field
	// in an ICMPv4ParamProblem message.
	icmpv4PointerOffset = 4

	// icmpv4SequenceOffset is the offset of the sequence field
	// in an ICMPv4EchoRequest/Reply message.
	icmpv4SequenceOffset = 6
)

// ICMPv4Type is the ICMP type field described in RFC 792.
type ICMPv4Type byte

// ICMPv4Code is the ICMP code field described in RFC 792.
type ICMPv4Code byte

// Typical values of ICMPv4Type defined in RFC 792.
const (
	ICMPv4EchoReply      ICMPv4Type = 0
	ICMPv4DstUnreachable ICMPv4Type = 3
	ICMPv4SrcQuench      ICMPv4Type = 4
	ICMPv4Redirect       ICMPv4Type = 5
	ICMPv4Echo           ICMPv4Type = 8
	ICMPv4TimeExceeded   ICMPv4Type = 11
	ICMPv4ParamProblem   ICMPv4Type = 12
	ICMPv4Timestamp      ICMPv4Type = 13
	ICMPv4TimestampReply ICMPv4Type = 14
	ICMPv4InfoRequest    ICMPv4Type = 15
	ICMPv4InfoReply      ICMPv4Type = 16
)

// ICMP codes for ICMPv4 Time Exceeded messages as defined in RFC 792.
const (
	ICMPv4TTLExceeded       ICMPv4Code = 0
	ICMPv4ReassemblyTimeout ICMPv4Code = 1
)

// ICMP codes for ICMPv4 Destination Unreachable messages as defined in RFC 792,
// RFC 1122 section 3.2.2.1 and RFC 1812 section 5.2.7.1.
const (
	ICMPv4NetUnreachable      ICMPv4Code = 0
	ICMPv4HostUnreachable     ICMPv4Code = 1
	ICMPv4ProtoUnreachable    ICMPv4Code = 2
	ICMPv4PortUnreachable     ICMPv4Code = 3
	ICMPv4FragmentationNeeded ICMPv4Code = 4
	ICMPv4NetProhibited       ICMPv4Code = 9
	ICMPv4HostProhibited      ICMPv4Code = 10
	ICMPv4AdminProhibited     ICMPv4Code = 13
)

// ICMPv4UnusedCode is a code to use in ICMP messages where no code is needed.
const ICMPv4UnusedCode ICMPv4Code = 0

// Type is the ICMP type field.
func (b ICMPv4) Type() ICMPv4Type { return ICMPv4Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv4) SetType(t ICMPv4Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv4) Code() ICMPv4Code { return ICMPv4Code(b[1]) }

// SetCode sets the ICMP code field.
func (b ICMPv4) SetCode(c ICMPv4Code) { b[1] = byte(c) }

// Pointer returns the pointer field in a Parameter Problem packet.
func (b ICMPv4) Pointer() byte { return b[icmpv4PointerOffset] }

// SetPointer sets the pointer field in a Parameter Problem packet.
func (b ICMPv4) SetPointer(c byte) { b[icmpv4PointerOffset] = c }

// Checksum is the ICMP checksum field.
func (b ICMPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4ChecksumOffset:])
}

// SetChecksum sets the ICMP checksum field.
func (b ICMPv4) SetChecksum(checksum uint16) {
	PutChecksum(b[icmpv4ChecksumOffset:], checksum)
}

// SourcePort implements Transport.SourcePort.
func (ICMPv4) SourcePort() uint16 {
	return 0
}

// DestinationPort implements Transport.DestinationPort.
func (ICMPv4) DestinationPort() uint16 {
	return 0
}

// SetSourcePort implements Transport.SetSourcePort.
func (ICMPv4) SetSourcePort(uint16) {
}

// SetDestinationPort implements Transport.SetDestinationPort.
func (ICMPv4) SetDestinationPort(uint16) {
}

// Payload implements Transport.Payload.
func (b ICMPv4) Payload() []byte {
	return b[ICMPv4PayloadOffset:]
}

// MTU retrieves the MTU field from an ICMPv4 message.
func (b ICMPv4) MTU() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4MTUOffset:])
}

// SetMTU sets the MTU field from an ICMPv4 message.
func (b ICMPv4) SetMTU(mtu uint16) {
	binary.BigEndian.PutUint16(b[icmpv4MTUOffset:], mtu)
}

// Ident retrieves the Ident field from an ICMPv4 message.
func (b ICMPv4) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4IdentOffset:])
}

// SetIdent sets the Ident field from an ICMPv4 message.
func (b ICMPv4) SetIdent(ident uint16) {
	binary.BigEndian.PutUint16(b[icmpv4IdentOffset:], ident)
}

// SetIdentWithChecksumUpdate sets the Ident field and updates the checksum.
func (b ICMPv4) SetIdentWithChecksumUpdate(new uint16) {
	old := b.Ident()
	b.SetIdent(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

// Sequence retrieves the Sequence field from an ICMPv4 message.
func (b ICMPv4) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4SequenceOffset:])
}

// SetSequence sets the Sequence field from an ICMPv4 message.
func (b ICMPv4) SetSequence(sequence uint16) {
	binary.BigEndian.PutUint16(b[icmpv4SequenceOffset:], sequence)
}

// ICMPv4Checksum calculates the ICMP checksum over the provided ICMP header,
// and payload.
func ICMPv4Checksum(h ICMPv4, payloadCsum uint16) uint16 {
	xsum := payloadCsum

	// h[2:4] is the checksum itself, skip it to avoid checksumming the checksum.
	xsum = Checksum(h[:2], xsum)
	xsum = Checksum(h[4:], xsum)

	return ^xsum
}
