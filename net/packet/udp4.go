// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import "encoding/binary"

// UDPHeader represents an UDP packet header.
type UDP4Header struct {
	IP4Header
	SrcPort uint16
	DstPort uint16
}

const (
	// udpHeaderLength is the size of the UDP packet header, not
	// including the outer IP header.
	udpHeaderLength = 8
)

func (UDP4Header) Len() int {
	return ip4HeaderLength + udpHeaderLength
}

func (h UDP4Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = UDP

	length := len(buf) - h.IP4Header.Len()
	binary.BigEndian.PutUint16(buf[20:22], h.SrcPort)
	binary.BigEndian.PutUint16(buf[22:24], h.DstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(length))
	binary.BigEndian.PutUint16(buf[26:28], 0) // blank checksum

	// UDP checksum with IP pseudo header.
	h.IP4Header.MarshalPseudo(buf)
	binary.BigEndian.PutUint16(buf[26:28], ipChecksum(buf[8:]))

	h.IP4Header.Marshal(buf)

	return nil
}

func (h *UDP4Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP4Header.ToResponse()
}
