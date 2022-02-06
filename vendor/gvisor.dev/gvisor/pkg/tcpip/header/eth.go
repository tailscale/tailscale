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
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

// EthernetFields contains the fields of an ethernet frame header. It is used to
// describe the fields of a frame that needs to be encoded.
type EthernetFields struct {
	// SrcAddr is the "MAC source" field of an ethernet frame header.
	SrcAddr tcpip.LinkAddress

	// DstAddr is the "MAC destination" field of an ethernet frame header.
	DstAddr tcpip.LinkAddress

	// Type is the "ethertype" field of an ethernet frame header.
	Type tcpip.NetworkProtocolNumber
}

// Ethernet represents an ethernet frame header stored in a byte array.
type Ethernet []byte

const (
	// EthernetMinimumSize is the minimum size of a valid ethernet frame.
	EthernetMinimumSize = 14

	// EthernetAddressSize is the size, in bytes, of an ethernet address.
	EthernetAddressSize = 6

	// UnspecifiedEthernetAddress is the unspecified ethernet address
	// (all bits set to 0).
	UnspecifiedEthernetAddress = tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00")

	// EthernetBroadcastAddress is an ethernet address that addresses every node
	// on a local link.
	EthernetBroadcastAddress = tcpip.LinkAddress("\xff\xff\xff\xff\xff\xff")

	// unicastMulticastFlagMask is the mask of the least significant bit in
	// the first octet (in network byte order) of an ethernet address that
	// determines whether the ethernet address is a unicast or multicast. If
	// the masked bit is a 1, then the address is a multicast, unicast
	// otherwise.
	//
	// See the IEEE Std 802-2001 document for more details. Specifically,
	// section 9.2.1 of http://ieee802.org/secmail/pdfocSP2xXA6d.pdf:
	// "A 48-bit universal address consists of two parts. The first 24 bits
	// correspond to the OUI as assigned by the IEEE, expect that the
	// assignee may set the LSB of the first octet to 1 for group addresses
	// or set it to 0 for individual addresses."
	unicastMulticastFlagMask = 1

	// unicastMulticastFlagByteIdx is the byte that holds the
	// unicast/multicast flag. See unicastMulticastFlagMask.
	unicastMulticastFlagByteIdx = 0
)

const (
	// EthernetProtocolAll is a catch-all for all protocols carried inside
	// an ethernet frame. It is mainly used to create packet sockets that
	// capture all traffic.
	EthernetProtocolAll tcpip.NetworkProtocolNumber = 0x0003

	// EthernetProtocolPUP is the PARC Universial Packet protocol ethertype.
	EthernetProtocolPUP tcpip.NetworkProtocolNumber = 0x0200
)

// Ethertypes holds the protocol numbers describing the payload of an ethernet
// frame. These types aren't necessarily supported by netstack, but can be used
// to catch all traffic of a type via packet endpoints.
var Ethertypes = []tcpip.NetworkProtocolNumber{
	EthernetProtocolAll,
	EthernetProtocolPUP,
}

// SourceAddress returns the "MAC source" field of the ethernet frame header.
func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

// DestinationAddress returns the "MAC destination" field of the ethernet frame
// header.
func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

// Type returns the "ethertype" field of the ethernet frame header.
func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

// Encode encodes all the fields of the ethernet frame header.
func (b Ethernet) Encode(e *EthernetFields) {
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)
}

// IsMulticastEthernetAddress returns true if the address is a multicast
// ethernet address.
func IsMulticastEthernetAddress(addr tcpip.LinkAddress) bool {
	if len(addr) != EthernetAddressSize {
		return false
	}

	return addr[unicastMulticastFlagByteIdx]&unicastMulticastFlagMask != 0
}

// IsValidUnicastEthernetAddress returns true if the address is a unicast
// ethernet address.
func IsValidUnicastEthernetAddress(addr tcpip.LinkAddress) bool {
	if len(addr) != EthernetAddressSize {
		return false
	}

	if addr == UnspecifiedEthernetAddress {
		return false
	}

	if addr[unicastMulticastFlagByteIdx]&unicastMulticastFlagMask != 0 {
		return false
	}

	return true
}

// EthernetAddressFromMulticastIPv4Address returns a multicast Ethernet address
// for a multicast IPv4 address.
//
// addr MUST be a multicast IPv4 address.
func EthernetAddressFromMulticastIPv4Address(addr tcpip.Address) tcpip.LinkAddress {
	var linkAddrBytes [EthernetAddressSize]byte
	// RFC 1112 Host Extensions for IP Multicasting
	//
	// 6.4. Extensions to an Ethernet Local Network Module:
	//
	// An IP host group address is mapped to an Ethernet multicast
	// address by placing the low-order 23-bits of the IP address
	// into the low-order 23 bits of the Ethernet multicast address
	// 01-00-5E-00-00-00 (hex).
	linkAddrBytes[0] = 0x1
	linkAddrBytes[2] = 0x5e
	linkAddrBytes[3] = addr[1] & 0x7F
	copy(linkAddrBytes[4:], addr[IPv4AddressSize-2:])
	return tcpip.LinkAddress(linkAddrBytes[:])
}

// EthernetAddressFromMulticastIPv6Address returns a multicast Ethernet address
// for a multicast IPv6 address.
//
// addr MUST be a multicast IPv6 address.
func EthernetAddressFromMulticastIPv6Address(addr tcpip.Address) tcpip.LinkAddress {
	// RFC 2464 Transmission of IPv6 Packets over Ethernet Networks
	//
	// 7. Address Mapping -- Multicast
	//
	// An IPv6 packet with a multicast destination address DST,
	// consisting of the sixteen octets DST[1] through DST[16], is
	// transmitted to the Ethernet multicast address whose first
	// two octets are the value 3333 hexadecimal and whose last
	// four octets are the last four octets of DST.
	linkAddrBytes := []byte(addr[IPv6AddressSize-EthernetAddressSize:])
	linkAddrBytes[0] = 0x33
	linkAddrBytes[1] = 0x33
	return tcpip.LinkAddress(linkAddrBytes[:])
}
