// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

type ICMPType uint8

const (
	ICMPEchoReply    ICMPType = 0x00
	ICMPEchoRequest  ICMPType = 0x08
	ICMPUnreachable  ICMPType = 0x03
	ICMPTimeExceeded ICMPType = 0x0b
)

func (t ICMPType) String() string {
	switch t {
	case ICMPEchoReply:
		return "EchoReply"
	case ICMPEchoRequest:
		return "EchoRequest"
	case ICMPUnreachable:
		return "Unreachable"
	case ICMPTimeExceeded:
		return "TimeExceeded"
	default:
		return "Unknown"
	}
}

type ICMPCode uint8

const (
	ICMPNoCode ICMPCode = 0
)

// ICMPHeader represents an ICMP packet header.
type ICMPHeader struct {
	IPHeader
	Type ICMPType
	Code ICMPCode
}

const (
	icmpHeaderLength = 4
	// icmpTotalHeaderLength is the length of all headers in a ICMP packet.
	icmpAllHeadersLength = ipHeaderLength + icmpHeaderLength
)

func (ICMPHeader) Len() int {
	return icmpAllHeadersLength
}

func (h ICMPHeader) Marshal(buf []byte) error {
	if len(buf) < icmpAllHeadersLength {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ICMP

	buf[20] = uint8(h.Type)
	buf[21] = uint8(h.Code)

	h.IPHeader.Marshal(buf)

	put16(buf[22:24], ipChecksum(buf))

	return nil
}

func (h *ICMPHeader) ToResponse() {
	h.Type = ICMPEchoReply
	h.Code = ICMPNoCode
	h.IPHeader.ToResponse()
}
