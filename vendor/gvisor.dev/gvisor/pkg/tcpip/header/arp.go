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
	// ARPProtocolNumber is the ARP network protocol number.
	ARPProtocolNumber tcpip.NetworkProtocolNumber = 0x0806

	// ARPSize is the size of an IPv4-over-Ethernet ARP packet.
	ARPSize = 28
)

// ARPHardwareType is the hardware type for LinkEndpoint in an ARP header.
type ARPHardwareType uint16

// Typical ARP HardwareType values. Some of the constants have to be specific
// values as they are egressed on the wire in the HTYPE field of an ARP header.
const (
	ARPHardwareNone ARPHardwareType = 0
	// ARPHardwareEther specifically is the HTYPE for Ethernet as specified
	// in the IANA list here:
	//
	// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
	ARPHardwareEther    ARPHardwareType = 1
	ARPHardwareLoopback ARPHardwareType = 2
)

// ARPOp is an ARP opcode.
type ARPOp uint16

// Typical ARP opcodes defined in RFC 826.
const (
	ARPRequest ARPOp = 1
	ARPReply   ARPOp = 2
)

// ARP is an ARP packet stored in a byte array as described in RFC 826.
type ARP []byte

const (
	hTypeOffset                 = 0
	protocolOffset              = 2
	haAddressSizeOffset         = 4
	protoAddressSizeOffset      = 5
	opCodeOffset                = 6
	senderHAAddressOffset       = 8
	senderProtocolAddressOffset = senderHAAddressOffset + EthernetAddressSize
	targetHAAddressOffset       = senderProtocolAddressOffset + IPv4AddressSize
	targetProtocolAddressOffset = targetHAAddressOffset + EthernetAddressSize
)

func (a ARP) hardwareAddressType() ARPHardwareType {
	return ARPHardwareType(binary.BigEndian.Uint16(a[hTypeOffset:]))
}

func (a ARP) protocolAddressSpace() uint16 { return binary.BigEndian.Uint16(a[protocolOffset:]) }
func (a ARP) hardwareAddressSize() int     { return int(a[haAddressSizeOffset]) }
func (a ARP) protocolAddressSize() int     { return int(a[protoAddressSizeOffset]) }

// Op is the ARP opcode.
func (a ARP) Op() ARPOp { return ARPOp(binary.BigEndian.Uint16(a[opCodeOffset:])) }

// SetOp sets the ARP opcode.
func (a ARP) SetOp(op ARPOp) {
	binary.BigEndian.PutUint16(a[opCodeOffset:], uint16(op))
}

// SetIPv4OverEthernet configures the ARP packet for IPv4-over-Ethernet.
func (a ARP) SetIPv4OverEthernet() {
	binary.BigEndian.PutUint16(a[hTypeOffset:], uint16(ARPHardwareEther))
	binary.BigEndian.PutUint16(a[protocolOffset:], uint16(IPv4ProtocolNumber))
	a[haAddressSizeOffset] = EthernetAddressSize
	a[protoAddressSizeOffset] = uint8(IPv4AddressSize)
}

// HardwareAddressSender is the link address of the sender.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) HardwareAddressSender() []byte {
	return a[senderHAAddressOffset : senderHAAddressOffset+EthernetAddressSize]
}

// ProtocolAddressSender is the protocol address of the sender.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) ProtocolAddressSender() []byte {
	return a[senderProtocolAddressOffset : senderProtocolAddressOffset+IPv4AddressSize]
}

// HardwareAddressTarget is the link address of the target.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) HardwareAddressTarget() []byte {
	return a[targetHAAddressOffset : targetHAAddressOffset+EthernetAddressSize]
}

// ProtocolAddressTarget is the protocol address of the target.
// It is a view on to the ARP packet so it can be used to set the value.
func (a ARP) ProtocolAddressTarget() []byte {
	return a[targetProtocolAddressOffset : targetProtocolAddressOffset+IPv4AddressSize]
}

// IsValid reports whether this is an ARP packet for IPv4 over Ethernet.
func (a ARP) IsValid() bool {
	if len(a) < ARPSize {
		return false
	}
	return a.hardwareAddressType() == ARPHardwareEther &&
		a.protocolAddressSpace() == uint16(IPv4ProtocolNumber) &&
		a.hardwareAddressSize() == EthernetAddressSize &&
		a.protocolAddressSize() == IPv4AddressSize
}
