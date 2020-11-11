// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"fmt"

	"inet.af/netaddr"
)

// IP4 is an IPv4 address.
type IP4 uint32

// IPFromNetaddr converts a netaddr.IP to an IP4. Panics if !ip.Is4.
func IP4FromNetaddr(ip netaddr.IP) IP4 {
	ipbytes := ip.As4()
	return IP4(binary.BigEndian.Uint32(ipbytes[:]))
}

// Netaddr converts ip to a netaddr.IP.
func (ip IP4) Netaddr() netaddr.IP {
	return netaddr.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func (ip IP4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// IsMulticast returns whether ip is a multicast address.
func (ip IP4) IsMulticast() bool {
	return byte(ip>>24)&0xf0 == 0xe0
}

// IsLinkLocalUnicast returns whether ip is a link-local unicast
// address.
func (ip IP4) IsLinkLocalUnicast() bool {
	return byte(ip>>24) == 169 && byte(ip>>16) == 254
}

// ip4HeaderLength is the length of an IPv4 header with no IP options.
const ip4HeaderLength = 20

// IP4Header represents an IPv4 packet header.
type IP4Header struct {
	IPProto IPProto
	IPID    uint16
	SrcIP   IP4
	DstIP   IP4
}

// Len implements Header.
func (h IP4Header) Len() int {
	return ip4HeaderLength
}

// Marshal implements Header.
func (h IP4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
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
	binary.BigEndian.PutUint32(buf[12:16], uint32(h.SrcIP)) // Src
	binary.BigEndian.PutUint32(buf[16:20], uint32(h.DstIP)) // Dst

	binary.BigEndian.PutUint16(buf[10:12], ip4Checksum(buf[0:20])) // Checksum

	return nil
}

// ToResponse implements Header.
func (h *IP4Header) ToResponse() {
	h.SrcIP, h.DstIP = h.DstIP, h.SrcIP
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
	binary.BigEndian.PutUint32(buf[8:12], uint32(h.SrcIP))
	binary.BigEndian.PutUint32(buf[12:16], uint32(h.DstIP))
	buf[16] = 0x0
	buf[17] = uint8(h.IPProto)
	binary.BigEndian.PutUint16(buf[18:20], uint16(length))
	return nil
}
