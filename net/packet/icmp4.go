// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

type ICMP4Type uint8

const (
	ICMP4EchoReply    ICMP4Type = 0x00
	ICMP4EchoRequest  ICMP4Type = 0x08
	ICMP4Unreachable  ICMP4Type = 0x03
	ICMP4TimeExceeded ICMP4Type = 0x0b
)

func (t ICMP4Type) String() string {
	switch t {
	case ICMP4EchoReply:
		return "EchoReply"
	case ICMP4EchoRequest:
		return "EchoRequest"
	case ICMP4Unreachable:
		return "Unreachable"
	case ICMP4TimeExceeded:
		return "TimeExceeded"
	default:
		return "Unknown"
	}
}

type ICMP4Code uint8

const (
	ICMP4NoCode ICMP4Code = 0
)

// ICMP4Header represents an ICMPv4 packet header.
type ICMP4Header struct {
	IP4Header
	Type ICMP4Type
	Code ICMP4Code
}

const (
	icmp4HeaderLength = 4
	// icmp4AllHeadersLength is the length of all headers in a ICMPv4 packet.
	icmp4AllHeadersLength = ip4HeaderLength + icmp4HeaderLength
)

func (ICMP4Header) Len() int {
	return icmp4AllHeadersLength
}

func (h ICMP4Header) Marshal(buf []byte) error {
	if len(buf) < icmp4AllHeadersLength {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ICMPv4

	buf[20] = uint8(h.Type)
	buf[21] = uint8(h.Code)

	h.IP4Header.Marshal(buf)

	put16(buf[22:24], ipChecksum(buf))

	return nil
}

func (h *ICMP4Header) ToResponse() {
	// TODO: this doesn't implement ToResponse correctly, as it
	// assumes the ICMP request type.
	h.Type = ICMP4EchoReply
	h.Code = ICMP4NoCode
	h.IP4Header.ToResponse()
}
