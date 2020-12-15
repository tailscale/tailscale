// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"fmt"

	"inet.af/netaddr"
)

// IP6 is an IPv6 address.
type IP6 struct {
	Hi, Lo uint64
}

// IP6FromRaw16 converts a raw 16-byte IPv6 address to an IP6.
func IP6FromRaw16(ip [16]byte) IP6 {
	return IP6{binary.BigEndian.Uint64(ip[:8]), binary.BigEndian.Uint64(ip[8:])}
}

// IP6FromNetaddr converts a netaddr.IP to an IP6. Panics if !ip.Is6.
func IP6FromNetaddr(ip netaddr.IP) IP6 {
	if !ip.Is6() {
		panic(fmt.Sprintf("IP6FromNetaddr called with non-v6 addr %q", ip))
	}
	return IP6FromRaw16(ip.As16())
}

// Netaddr converts ip to a netaddr.IP.
func (ip IP6) Netaddr() netaddr.IP {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], ip.Hi)
	binary.BigEndian.PutUint64(b[8:], ip.Lo)
	return netaddr.IPFrom16(b)
}

func (ip IP6) String() string {
	return ip.Netaddr().String()
}

func (ip IP6) IsMulticast() bool {
	return (ip.Hi >> 56) == 0xFF
}

func (ip IP6) IsLinkLocalUnicast() bool {
	return (ip.Hi >> 48) == 0xFE80
}

// ip6HeaderLength is the length of an IPv6 header with no IP options.
const ip6HeaderLength = 40

// IP6Header represents an IPv6 packet header.
type IP6Header struct {
	IPProto IPProto
	IPID    uint32 // only lower 20 bits used
	SrcIP   IP6
	DstIP   IP6
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
	binary.BigEndian.PutUint64(buf[8:16], h.SrcIP.Hi)
	binary.BigEndian.PutUint64(buf[16:24], h.SrcIP.Lo)
	binary.BigEndian.PutUint64(buf[24:32], h.DstIP.Hi)
	binary.BigEndian.PutUint64(buf[32:40], h.DstIP.Lo)

	return nil
}

// ToResponse implements Header.
func (h *IP6Header) ToResponse() {
	h.SrcIP, h.DstIP = h.DstIP, h.SrcIP
	// Flip the bits in the IPID. If incoming IPIDs are distinct, so are these.
	h.IPID = (^h.IPID) & 0x000FFFFF
}

// marshalPseudo serializes h into buf in the "pseudo-header" form
// required when calculating UDP checksums.
func (h IP6Header) marshalPseudo(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}

	binary.BigEndian.PutUint64(buf[:8], h.SrcIP.Hi)
	binary.BigEndian.PutUint64(buf[8:16], h.SrcIP.Lo)
	binary.BigEndian.PutUint64(buf[16:24], h.DstIP.Hi)
	binary.BigEndian.PutUint64(buf[24:32], h.DstIP.Lo)
	binary.BigEndian.PutUint32(buf[32:36], uint32(len(buf)-h.Len()))
	buf[36] = 0
	buf[37] = 0
	buf[38] = 0
	buf[39] = 17 // NextProto
	return nil
}
