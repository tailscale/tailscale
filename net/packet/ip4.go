// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"tailscale.com/types/ipproto"
)

// ip4HeaderLength is the length of an IPv4 header with no IP options.
const ip4HeaderLength = 20

// IP4Header represents an IPv4 packet header.
type IP4Header struct {
	IPProto ipproto.Proto
	IPID    uint16
	Src     netip.Addr
	Dst     netip.Addr
}

// Len implements Header.
func (h IP4Header) Len() int {
	return ip4HeaderLength
}

var errWrongFamily = errors.New("wrong address family for src/dst IP")

// Marshal implements Header.
func (h IP4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	if !h.Src.Is4() || !h.Dst.Is4() {
		return errWrongFamily
	}

	buf[0] = 0x40 | (byte(h.Len() >> 2))                   // IPv4 + IHL
	buf[1] = 0x00                                          // DSCP + ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf))) // Total length
	binary.BigEndian.PutUint16(buf[4:6], h.IPID)           // ID
	binary.BigEndian.PutUint16(buf[6:8], 0)                // Flags + fragment offset
	buf[8] = 64                                            // TTL
	buf[9] = uint8(h.IPProto)                              // Inner protocol
	// Blank checksum. This is necessary even though we overwrite
	// it later, because the checksum computation runs over these
	// bytes and expects them to be zero.
	binary.BigEndian.PutUint16(buf[10:12], 0)
	src := h.Src.As4()
	dst := h.Dst.As4()
	copy(buf[12:16], src[:])
	copy(buf[16:20], dst[:])

	binary.BigEndian.PutUint16(buf[10:12], ip4Checksum(buf[0:20])) // Checksum

	return nil
}

// ToResponse implements Header.
func (h *IP4Header) ToResponse() {
	h.Src, h.Dst = h.Dst, h.Src
	// Flip the bits in the IPID. If incoming IPIDs are distinct, so are these.
	h.IPID = ^h.IPID
}

// ip4Checksum computes an IPv4 checksum, as specified in
// https://tools.ietf.org/html/rfc1071
func ip4Checksum(b []byte) uint16 {
	var ac uint32
	i := 0
	n := len(b)
	for n >= 2 {
		ac += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint32(b[i]) << 8
	}
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(^ac)
}

// ip4PseudoHeaderOffset is the number of bytes by which the IPv4 UDP
// pseudo-header is smaller than the real IPv4 header.
const ip4PseudoHeaderOffset = 8

// marshalPseudo serializes h into buf in the "pseudo-header" form
// required when calculating UDP checksums. The pseudo-header starts
// at buf[ip4PseudoHeaderOffset] so as to abut the following UDP
// header, while leaving enough space in buf for a full IPv4 header.
func (h IP4Header) marshalPseudo(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	length := len(buf) - h.Len()
	src, dst := h.Src.As4(), h.Dst.As4()
	copy(buf[8:12], src[:])
	copy(buf[12:16], dst[:])
	buf[16] = 0x0
	buf[17] = uint8(h.IPProto)
	binary.BigEndian.PutUint16(buf[18:20], uint16(length))
	return nil
}
