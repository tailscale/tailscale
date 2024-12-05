// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/types/ipproto"
)

// ip6HeaderLength is the length of an IPv6 header with no IP options.
const ip6HeaderLength = 40

// IP6Header represents an IPv6 packet header.
type IP6Header struct {
	IPProto ipproto.Proto
	IPID    uint32 // only lower 20 bits used
	Src     netip.Addr
	Dst     netip.Addr
}

// Len implements Header.
func (h IP6Header) Len() int {
	return ip6HeaderLength
}

// Marshal implements Header.
func (h IP6Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	binary.BigEndian.PutUint32(buf[:4], h.IPID&0x000FFFFF)
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(buf)-ip6HeaderLength)) // Total length
	buf[6] = uint8(h.IPProto)                                              // Inner protocol
	buf[7] = 64                                                            // TTL
	src, dst := h.Src.As16(), h.Dst.As16()
	copy(buf[8:24], src[:])
	copy(buf[24:40], dst[:])

	return nil
}

// ToResponse implements Header.
func (h *IP6Header) ToResponse() {
	h.Src, h.Dst = h.Dst, h.Src
	// Flip the bits in the IPID. If incoming IPIDs are distinct, so are these.
	h.IPID = (^h.IPID) & 0x000FFFFF
}

// marshalPseudo serializes h into buf in the "pseudo-header" form
// required when calculating UDP checksums.
func (h IP6Header) marshalPseudo(buf []byte, proto ipproto.Proto) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	src, dst := h.Src.As16(), h.Dst.As16()
	copy(buf[:16], src[:])
	copy(buf[16:32], dst[:])
	binary.BigEndian.PutUint32(buf[32:36], uint32(len(buf)-h.Len()))
	buf[36] = 0
	buf[37] = 0
	buf[38] = 0
	buf[39] = byte(proto) // NextProto
	return nil
}
