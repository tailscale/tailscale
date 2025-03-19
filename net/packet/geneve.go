// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// GeneveFixedHeaderLength is the length of the fixed size portion of the
	// Geneve header, in bytes.
	GeneveFixedHeaderLength = 8
)

const (
	// GeneveProtocolDisco is the IEEE 802 Ethertype number used to represent
	// the Tailscale Disco protocol in a Geneve header.
	GeneveProtocolDisco uint16 = 0x7A11
	// GeneveProtocolWireGuard is the IEEE 802 Ethertype number used to represent the
	// WireGuard protocol in a Geneve header.
	GeneveProtocolWireGuard uint16 = 0x7A12
)

// GeneveHeader represents the fixed size Geneve header from RFC8926.
// TLVs/options are not implemented/supported.
//
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        Virtual Network Identifier (VNI)       |    Reserved   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type GeneveHeader struct {
	// Ver (2 bits): The current version number is 0. Packets received by a
	// tunnel endpoint with an unknown version MUST be dropped. Transit devices
	// interpreting Geneve packets with an unknown version number MUST treat
	// them as UDP packets with an unknown payload.
	Version uint8

	// Protocol Type (16 bits): The type of protocol data unit appearing after
	// the Geneve header. This follows the Ethertype [ETYPES] convention, with
	// Ethernet itself being represented by the value 0x6558.
	Protocol uint16

	// Virtual Network Identifier (VNI) (24 bits): An identifier for a unique
	// element of a virtual network. In many situations, this may represent an
	// L2 segment; however, the control plane defines the forwarding semantics
	// of decapsulated packets. The VNI MAY be used as part of ECMP forwarding
	// decisions or MAY be used as a mechanism to distinguish between
	// overlapping address spaces contained in the encapsulated packet when load
	// balancing across CPUs.
	VNI uint32

	// O (1 bit): Control packet. This packet contains a control message.
	// Control messages are sent between tunnel endpoints. Tunnel endpoints MUST
	// NOT forward the payload, and transit devices MUST NOT attempt to
	// interpret it. Since control messages are less frequent, it is RECOMMENDED
	// that tunnel endpoints direct these packets to a high-priority control
	// queue (for example, to direct the packet to a general purpose CPU from a
	// forwarding Application-Specific Integrated Circuit (ASIC) or to separate
	// out control traffic on a NIC). Transit devices MUST NOT alter forwarding
	// behavior on the basis of this bit, such as ECMP link selection.
	Control bool
}

// Encode encodes GeneveHeader into b. If len(b) < GeneveFixedHeaderLength an
// io.ErrShortBuffer error is returned.
func (h *GeneveHeader) Encode(b []byte) error {
	if len(b) < GeneveFixedHeaderLength {
		return io.ErrShortBuffer
	}
	if h.Version > 3 {
		return errors.New("version must be <= 3")
	}
	b[0] = 0
	b[1] = 0
	b[0] |= h.Version << 6
	if h.Control {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:], h.Protocol)
	if h.VNI > 1<<24-1 {
		return errors.New("VNI must be <= 2^24-1")
	}
	binary.BigEndian.PutUint32(b[4:], h.VNI<<8)
	return nil
}

// Decode decodes GeneveHeader from b. If len(b) < GeneveFixedHeaderLength an
// io.ErrShortBuffer error is returned.
func (h *GeneveHeader) Decode(b []byte) error {
	if len(b) < GeneveFixedHeaderLength {
		return io.ErrShortBuffer
	}
	h.Version = b[0] >> 6
	if b[1]&0x80 != 0 {
		h.Control = true
	}
	h.Protocol = binary.BigEndian.Uint16(b[2:])
	h.VNI = binary.BigEndian.Uint32(b[4:]) >> 8
	return nil
}
