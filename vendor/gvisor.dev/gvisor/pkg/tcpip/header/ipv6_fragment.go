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

const (
	nextHdrFrag = 0
	fragOff     = 2
	more        = 3
	idV6        = 4
)

var _ IPv6SerializableExtHdr = (*IPv6SerializableFragmentExtHdr)(nil)

// IPv6SerializableFragmentExtHdr is used to serialize an IPv6 fragment
// extension header as defined in RFC 8200 section 4.5.
type IPv6SerializableFragmentExtHdr struct {
	// FragmentOffset is the "fragment offset" field of an IPv6 fragment.
	FragmentOffset uint16

	// M is the "more" field of an IPv6 fragment.
	M bool

	// Identification is the "identification" field of an IPv6 fragment.
	Identification uint32
}

// identifier implements IPv6SerializableFragmentExtHdr.
func (h *IPv6SerializableFragmentExtHdr) identifier() IPv6ExtensionHeaderIdentifier {
	return IPv6FragmentHeader
}

// length implements IPv6SerializableFragmentExtHdr.
func (h *IPv6SerializableFragmentExtHdr) length() int {
	return IPv6FragmentHeaderSize
}

// serializeInto implements IPv6SerializableFragmentExtHdr.
func (h *IPv6SerializableFragmentExtHdr) serializeInto(nextHeader uint8, b []byte) int {
	// Prevent too many bounds checks.
	_ = b[IPv6FragmentHeaderSize:]
	binary.BigEndian.PutUint32(b[idV6:], h.Identification)
	binary.BigEndian.PutUint16(b[fragOff:], h.FragmentOffset<<ipv6FragmentExtHdrFragmentOffsetShift)
	b[nextHdrFrag] = nextHeader
	if h.M {
		b[more] |= ipv6FragmentExtHdrMFlagMask
	}
	return IPv6FragmentHeaderSize
}

// IPv6Fragment represents an ipv6 fragment header stored in a byte array.
// Most of the methods of IPv6Fragment access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv6Fragment before using other methods.
type IPv6Fragment []byte

const (
	// IPv6FragmentHeader header is the number used to specify that the next
	// header is a fragment header, per RFC 2460.
	IPv6FragmentHeader = 44

	// IPv6FragmentHeaderSize is the size of the fragment header.
	IPv6FragmentHeaderSize = 8
)

// IsValid performs basic validation on the fragment header.
func (b IPv6Fragment) IsValid() bool {
	return len(b) >= IPv6FragmentHeaderSize
}

// NextHeader returns the value of the "next header" field of the ipv6 fragment.
func (b IPv6Fragment) NextHeader() uint8 {
	return b[nextHdrFrag]
}

// FragmentOffset returns the "fragment offset" field of the ipv6 fragment.
func (b IPv6Fragment) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[fragOff:]) >> 3
}

// More returns the "more" field of the ipv6 fragment.
func (b IPv6Fragment) More() bool {
	return b[more]&1 > 0
}

// Payload implements Network.Payload.
func (b IPv6Fragment) Payload() []byte {
	return b[IPv6FragmentHeaderSize:]
}

// ID returns the value of the identifier field of the ipv6 fragment.
func (b IPv6Fragment) ID() uint32 {
	return binary.BigEndian.Uint32(b[idV6:])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv6Fragment) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}

// The functions below have been added only to satisfy the Network interface.

// Checksum is not supported by IPv6Fragment.
func (b IPv6Fragment) Checksum() uint16 {
	panic("not supported")
}

// SourceAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SourceAddress() tcpip.Address {
	panic("not supported")
}

// DestinationAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) DestinationAddress() tcpip.Address {
	panic("not supported")
}

// SetSourceAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SetSourceAddress(tcpip.Address) {
	panic("not supported")
}

// SetDestinationAddress is not supported by IPv6Fragment.
func (b IPv6Fragment) SetDestinationAddress(tcpip.Address) {
	panic("not supported")
}

// SetChecksum is not supported by IPv6Fragment.
func (b IPv6Fragment) SetChecksum(uint16) {
	panic("not supported")
}

// TOS is not supported by IPv6Fragment.
func (b IPv6Fragment) TOS() (uint8, uint32) {
	panic("not supported")
}

// SetTOS is not supported by IPv6Fragment.
func (b IPv6Fragment) SetTOS(t uint8, l uint32) {
	panic("not supported")
}
