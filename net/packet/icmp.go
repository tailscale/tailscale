// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	crand "crypto/rand"

	"encoding/binary"
	"net/netip"
)

// ICMPEchoPayload generates a new random ID/Sequence pair, and returns a uint32
// derived from them, along with the id, sequence and given payload in a buffer.
// It returns an error if the random source could not be read.
func ICMPEchoPayload(payload []byte) (idSeq uint32, buf []byte) {
	buf = make([]byte, len(payload)+4)

	// make a completely random id/sequence combo, which is very unlikely to
	// collide with a running ping sequence on the host system. Errors are
	// ignored, that would result in collisions, but errors reading from the
	// random device are rare, and will cause this process universe to soon end.
	crand.Read(buf[:4])

	idSeq = binary.LittleEndian.Uint32(buf)
	copy(buf[4:], payload)

	return
}

// icmpDestUnreachableUnusedLen is the number of unused bytes that both ICMPv4
// and ICMPv6 "Destination Unreachable" messages have between header and bits
// from the invoking packet.
const icmpDestUnreachableUnusedLen = 4
const minIPv6MTU = 1280 // RFC 2460, section 5

// GenerateICMPHostUnreachable builds an ICMPv4 or ICMPv6 "Destination
// Unreachable" message according to RFC 792 and RFC 4443, section 3.1.
// from and to must both be of the same address family; otherwise
// GenerateICMPHostUnreachable returns nil.
func GenerateICMPHostUnreachable(from, to netip.Addr, invoking *Parsed) []byte {
	buf := invoking.Buffer()
	switch {
	case from.Is4() && to.Is4():
		// RFC 792
		//     0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     Type      |     Code      |          Checksum             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                             unused                            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |      Internet Header + 64 bits of Original Data Datagram      |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		ipHeaderLen := len(buf) - len(invoking.Transport())
		return Generate(ICMP4Header{
			IP4Header: IP4Header{Src: from, Dst: to},
			Type:      ICMP4Unreachable,
			Code:      ICMP4HostUnreachable,
		}, icmpDestUnreachablePayload(buf, ipHeaderLen+8))
	case from.Is6() && to.Is6():
		// RFC 4443, section 3.1
		//        0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     Type      |     Code      |          Checksum             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                             Unused                            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                    As much of invoking packet                 |
		// +                as possible without the ICMPv6 packet          +
		// |                exceeding the minimum IPv6 MTU                 |
		maxOrig := minIPv6MTU - (ICMP6Header{}).Len() - icmpDestUnreachableUnusedLen
		return Generate(ICMP6Header{
			IP6Header: IP6Header{Src: from, Dst: to},
			Type:      ICMP6Unreachable,
			Code:      ICMP6AddressUnreachable,
		}, icmpDestUnreachablePayload(buf, maxOrig))
	default:
		return nil
	}
}

// icmpDestUnreachablePayload composes the payload for an ICMP "Destination Unreachable" packet.
func icmpDestUnreachablePayload(orig []byte, maxOrig int) []byte {
	n := min(len(orig), maxOrig)
	payload := make([]byte, icmpDestUnreachableUnusedLen+n)
	copy(payload[icmpDestUnreachableUnusedLen:], orig[:n])
	return payload
}
