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
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// MaxIPPacketSize is the maximum supported IP packet size, excluding
	// jumbograms. The maximum IPv4 packet size is 64k-1 (total size must fit
	// in 16 bits). For IPv6, the payload max size (excluding jumbograms) is
	// 64k-1 (also needs to fit in 16 bits). So we use 64k - 1 + 2 * m, where
	// m is the minimum IPv6 header size; we leave room for some potential
	// IP options.
	MaxIPPacketSize = 0xffff + 2*IPv6MinimumSize
)

// Transport offers generic methods to query and/or update the fields of the
// header of a transport protocol buffer.
type Transport interface {
	// SourcePort returns the value of the "source port" field.
	SourcePort() uint16

	// Destination returns the value of the "destination port" field.
	DestinationPort() uint16

	// Checksum returns the value of the "checksum" field.
	Checksum() uint16

	// SetSourcePort sets the value of the "source port" field.
	SetSourcePort(uint16)

	// SetDestinationPort sets the value of the "destination port" field.
	SetDestinationPort(uint16)

	// SetChecksum sets the value of the "checksum" field.
	SetChecksum(uint16)

	// Payload returns the data carried in the transport buffer.
	Payload() []byte
}

// ChecksummableTransport is a Transport that supports checksumming.
type ChecksummableTransport interface {
	Transport

	// SetSourcePortWithChecksumUpdate sets the source port and updates
	// the checksum.
	//
	// The receiver's checksum must be a fully calculated checksum.
	SetSourcePortWithChecksumUpdate(port uint16)

	// SetDestinationPortWithChecksumUpdate sets the destination port and updates
	// the checksum.
	//
	// The receiver's checksum must be a fully calculated checksum.
	SetDestinationPortWithChecksumUpdate(port uint16)

	// UpdateChecksumPseudoHeaderAddress updates the checksum to reflect an
	// updated address in the pseudo header.
	//
	// If fullChecksum is true, the receiver's checksum field is assumed to hold a
	// fully calculated checksum. Otherwise, it is assumed to hold a partially
	// calculated checksum which only reflects the pseudo header.
	UpdateChecksumPseudoHeaderAddress(old, new tcpip.Address, fullChecksum bool)
}

// Network offers generic methods to query and/or update the fields of the
// header of a network protocol buffer.
type Network interface {
	// SourceAddress returns the value of the "source address" field.
	SourceAddress() tcpip.Address

	// DestinationAddress returns the value of the "destination address"
	// field.
	DestinationAddress() tcpip.Address

	// Checksum returns the value of the "checksum" field.
	Checksum() uint16

	// SetSourceAddress sets the value of the "source address" field.
	SetSourceAddress(tcpip.Address)

	// SetDestinationAddress sets the value of the "destination address"
	// field.
	SetDestinationAddress(tcpip.Address)

	// SetChecksum sets the value of the "checksum" field.
	SetChecksum(uint16)

	// TransportProtocol returns the number of the transport protocol
	// stored in the payload.
	TransportProtocol() tcpip.TransportProtocolNumber

	// Payload returns a byte slice containing the payload of the network
	// packet.
	Payload() []byte

	// TOS returns the values of the "type of service" and "flow label" fields.
	TOS() (uint8, uint32)

	// SetTOS sets the values of the "type of service" and "flow label" fields.
	SetTOS(t uint8, l uint32)
}

// ChecksummableNetwork is a Network that supports checksumming.
type ChecksummableNetwork interface {
	Network

	// SetSourceAddressAndChecksum sets the source address and updates the
	// checksum to reflect the new address.
	SetSourceAddressWithChecksumUpdate(tcpip.Address)

	// SetDestinationAddressAndChecksum sets the destination address and
	// updates the checksum to reflect the new address.
	SetDestinationAddressWithChecksumUpdate(tcpip.Address)
}
