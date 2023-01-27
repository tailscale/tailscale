// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"

	"tailscale.com/types/ipproto"
)

// UDP6Header is an IPv6+UDP header.
type UDP6Header struct {
	IP6Header
	SrcPort uint16
	DstPort uint16
}

// Len implements Header.
func (h UDP6Header) Len() int {
	return h.IP6Header.Len() + udpHeaderLength
}

// Marshal implements Header.
func (h UDP6Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ipproto.UDP

	length := len(buf) - h.IP6Header.Len()
	binary.BigEndian.PutUint16(buf[40:42], h.SrcPort)
	binary.BigEndian.PutUint16(buf[42:44], h.DstPort)
	binary.BigEndian.PutUint16(buf[44:46], uint16(length))
	binary.BigEndian.PutUint16(buf[46:48], 0) // blank checksum

	// UDP checksum with IP pseudo header.
	h.IP6Header.marshalPseudo(buf, ipproto.UDP)
	binary.BigEndian.PutUint16(buf[46:48], ip4Checksum(buf[:]))

	h.IP6Header.Marshal(buf)

	return nil
}

// ToResponse implements Header.
func (h *UDP6Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP6Header.ToResponse()
}
