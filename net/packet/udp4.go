// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

// UDPHeader represents an UDP packet header.
type UDP4Header struct {
	IP4Header
	SrcPort uint16
	DstPort uint16
}

const (
	udpHeaderLength = 8
	// udpTotalHeaderLength is the length of all headers in a UDP packet.
	udpTotalHeaderLength = ip4HeaderLength + udpHeaderLength
)

func (UDP4Header) Len() int {
	return udpTotalHeaderLength
}

func (h UDP4Header) Marshal(buf []byte) error {
	if len(buf) < udpTotalHeaderLength {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = UDP

	length := len(buf) - h.IP4Header.Len()
	put16(buf[20:22], h.SrcPort)
	put16(buf[22:24], h.DstPort)
	put16(buf[24:26], uint16(length))
	put16(buf[26:28], 0) // blank checksum

	h.IP4Header.MarshalPseudo(buf)

	// UDP checksum with IP pseudo header.
	put16(buf[26:28], ipChecksum(buf[8:]))

	h.IP4Header.Marshal(buf)

	return nil
}

func (h *UDP4Header) ToResponse() {
	h.SrcPort, h.DstPort = h.DstPort, h.SrcPort
	h.IP4Header.ToResponse()
}
