// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"

	"tailscale.com/types/ipproto"
)

// udpHeaderLength is the size of the UDP packet header, not including
// the outer IP header.
const udpHeaderLength = 8

// UDP4Header is an IPv4+UDP header.
type UDP4Header struct {
	IP4Header
	SrcPort uint16
	DstPort uint16
}

// Len implements Header.
func (h UDP4Header) Len() int {
	return h.IP4Header.Len() + udpHeaderLength
}

// Marshal implements Header.
func (h UDP4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ipproto.UDP

	length := len(buf) - h.IP4Header.Len()
	binary.BigEndian.PutUint16(buf[20:22], h.SrcPort)
	binary.BigEndian.PutUint16(buf[22:24], h.DstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(length))
	binary.BigEndian.PutUint16(buf[26:28], 0) // blank checksum

	// UDP checksum with IP pseudo header.
	h.IP4Header.marshalPseudo(buf)
	binary.BigEndian.PutUint16(buf[26:28], ip4Checksum(buf[ip4PseudoHeaderOffset:]))

	h.IP4Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *UDP4Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP4Header.ToResponse()
}
