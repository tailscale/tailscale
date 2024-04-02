// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"

	"tailscale.com/types/ipproto"
)

// icmp6HeaderLength is the size of the ICMPv6 packet header, not
// including the outer IP layer or the variable "response data"
// trailer.
const icmp6HeaderLength = 4

// ICMP6Type is an ICMPv6 type, as specified in
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
type ICMP6Type uint8

const (
	ICMP6Unreachable  ICMP6Type = 1
	ICMP6PacketTooBig ICMP6Type = 2
	ICMP6TimeExceeded ICMP6Type = 3
	ICMP6ParamProblem ICMP6Type = 4
	ICMP6EchoRequest  ICMP6Type = 128
	ICMP6EchoReply    ICMP6Type = 129
)

func (t ICMP6Type) String() string {
	switch t {
	case ICMP6Unreachable:
		return "Unreachable"
	case ICMP6PacketTooBig:
		return "PacketTooBig"
	case ICMP6TimeExceeded:
		return "TimeExceeded"
	case ICMP6ParamProblem:
		return "ParamProblem"
	case ICMP6EchoRequest:
		return "EchoRequest"
	case ICMP6EchoReply:
		return "EchoReply"
	default:
		return "Unknown"
	}
}

// ICMP6Code is an ICMPv6 code, as specified in
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
type ICMP6Code uint8

const (
	ICMP6NoCode ICMP6Code = 0
)

// ICMP6Header is an IPv4+ICMPv4 header.
type ICMP6Header struct {
	IP6Header
	Type ICMP6Type
	Code ICMP6Code
}

// Len implements Header.
func (h ICMP6Header) Len() int {
	return h.IP6Header.Len() + icmp6HeaderLength
}

// Marshal implements Header.
func (h ICMP6Header) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	// The caller does not need to set this.
	h.IPProto = ipproto.ICMPv6

	h.IP6Header.Marshal(buf)

	const o = ip6HeaderLength // start offset of ICMPv6 header
	buf[o+0] = uint8(h.Type)
	buf[o+1] = uint8(h.Code)
	buf[o+2] = 0 // checksum, to be filled in later
	buf[o+3] = 0 // checksum, to be filled in later
	return nil
}

// ToResponse implements Header. TODO: it doesn't implement it
// correctly, instead it statically generates an ICMP Echo Reply
// packet.
func (h *ICMP6Header) ToResponse() {
	// TODO: this doesn't implement ToResponse correctly, as it
	// assumes the ICMP request type.
	h.Type = ICMP6EchoReply
	h.Code = ICMP6NoCode
	h.IP6Header.ToResponse()
}

// WriteChecksum implements HeaderChecksummer, writing just the checksum bytes
// into the otherwise fully marshaled ICMP6 packet p (which should include the
// IPv6 header, ICMPv6 header, and payload).
func (h ICMP6Header) WriteChecksum(p []byte) {
	const payOff = ip6HeaderLength + icmp6HeaderLength
	xsum := icmp6Checksum(p[ip6HeaderLength:payOff], h.Src.As16(), h.Dst.As16(), p[payOff:])
	binary.BigEndian.PutUint16(p[ip6HeaderLength+2:], xsum)
}

// Adapted from gVisor:

// icmp6Checksum calculates the ICMP checksum over the provided ICMPv6
// header (without the IPv6 header), IPv6 src/dst addresses and the
// payload.
//
// The header's existing checksum must be zeroed.
func icmp6Checksum(header []byte, src, dst [16]byte, payload []byte) uint16 {
	// Calculate the IPv6 pseudo-header upper-layer checksum.
	xsum := checksumBytes(src[:], 0)
	xsum = checksumBytes(dst[:], xsum)

	var scratch [4]byte
	binary.BigEndian.PutUint32(scratch[:], uint32(len(header)+len(payload)))
	xsum = checksumBytes(scratch[:], xsum)
	xsum = checksumBytes(append(scratch[:0], 0, 0, 0, uint8(ipproto.ICMPv6)), xsum)
	xsum = checksumBytes(payload, xsum)

	var hdrz [icmp6HeaderLength]byte
	copy(hdrz[:], header)
	// Zero out the header.
	hdrz[2] = 0
	hdrz[3] = 0
	xsum = ^checksumBytes(hdrz[:], xsum)
	return xsum
}

// checksumCombine combines the two uint16 to form their
// checksum. This is done by adding them and the carry.
//
// Note that checksum a must have been computed on an even number of
// bytes.
func checksumCombine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}

// checksumBytes calculates the checksum (as defined in RFC 1071) of
// the bytes in buf.
//
// The initial checksum must have been computed on an even number of bytes.
func checksumBytes(buf []byte, initial uint16) uint16 {
	v := uint32(initial)

	odd := len(buf)%2 == 1
	if odd {
		v += uint32(buf[0])
		buf = buf[1:]
	}

	n := len(buf)
	odd = n&1 != 0
	if odd {
		n--
		v += uint32(buf[n]) << 8
	}

	for i := 0; i < n; i += 2 {
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
	}

	return checksumCombine(uint16(v), uint16(v>>16))
}
