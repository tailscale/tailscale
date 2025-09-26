// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package checksum provides functions for updating checksums in parsed packets.
package checksum

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// UpdateSrcAddr updates the source address in the packet buffer (e.g. during
// SNAT). It also updates the checksum. Currently (2023-09-22) only TCP/UDP/ICMP
// is supported. It panics if provided with an address in a different
// family to the parsed packet.
func UpdateSrcAddr(q *packet.Parsed, src netip.Addr) {
	if src.Is6() && q.IPVersion != 6 {
		panic("UpdateSrcAddr: cannot write IPv6 address to v4 packet")
	} else if src.Is4() && q.IPVersion != 4 {
		panic("UpdateSrcAddr: cannot write IPv4 address to v6 packet")
	}
	q.CaptureMeta.DidSNAT = true
	q.CaptureMeta.OriginalSrc = q.Src

	old := q.Src.Addr()
	q.Src = netip.AddrPortFrom(src, q.Src.Port())

	b := q.Buffer()
	if src.Is6() {
		v6 := src.As16()
		copy(b[8:24], v6[:])
		updateV6PacketChecksums(q, old, src)
	} else {
		v4 := src.As4()
		copy(b[12:16], v4[:])
		updateV4PacketChecksums(q, old, src)
	}
}

// UpdateDstAddr updates the destination address in the packet buffer (e.g. during
// DNAT). It also updates the checksum. Currently (2022-12-10) only TCP/UDP/ICMP
// is supported. It panics if provided with an address in a different
// family to the parsed packet.
func UpdateDstAddr(q *packet.Parsed, dst netip.Addr) {
	if dst.Is6() && q.IPVersion != 6 {
		panic("UpdateDstAddr: cannot write IPv6 address to v4 packet")
	} else if dst.Is4() && q.IPVersion != 4 {
		panic("UpdateDstAddr: cannot write IPv4 address to v6 packet")
	}
	q.CaptureMeta.DidDNAT = true
	q.CaptureMeta.OriginalDst = q.Dst

	old := q.Dst.Addr()
	q.Dst = netip.AddrPortFrom(dst, q.Dst.Port())

	b := q.Buffer()
	if dst.Is6() {
		v6 := dst.As16()
		copy(b[24:40], v6[:])
		updateV6PacketChecksums(q, old, dst)
	} else {
		v4 := dst.As4()
		copy(b[16:20], v4[:])
		updateV4PacketChecksums(q, old, dst)
	}
}

// updateV4PacketChecksums updates the checksums in the packet buffer.
// Currently (2023-03-01) only TCP/UDP/ICMP over IPv4 is supported.
// p is modified in place.
// If p.IPProto is unknown, only the IP header checksum is updated.
func updateV4PacketChecksums(p *packet.Parsed, old, new netip.Addr) {
	if len(p.Buffer()) < 12 {
		// Not enough space for an IPv4 header.
		return
	}
	o4, n4 := old.As4(), new.As4()

	// First update the checksum in the IP header.
	updateV4Checksum(p.Buffer()[10:12], o4[:], n4[:])

	// Now update the transport layer checksums, where applicable.
	tr := p.Transport()
	switch p.IPProto {
	case ipproto.UDP, ipproto.DCCP:
		if len(tr) < minUDPSize {
			// Not enough space for a UDP header.
			return
		}
		updateV4Checksum(tr[6:8], o4[:], n4[:])
	case ipproto.TCP:
		if len(tr) < minTCPSize {
			// Not enough space for a TCP header.
			return
		}
		updateV4Checksum(tr[16:18], o4[:], n4[:])
	case ipproto.GRE:
		if len(tr) < 6 {
			// Not enough space for a GRE header.
			return
		}
		if tr[0] == 1 { // checksum present
			updateV4Checksum(tr[4:6], o4[:], n4[:])
		}
	case ipproto.SCTP, ipproto.ICMPv4:
		// No transport layer update required.
	}
}

const (
	minUDPSize    = 8
	minTCPSize    = 20
	minICMPv6Size = 8
	minIPv6Header = 40

	offsetICMPv6Checksum = 2
	offsetUDPChecksum    = 6
	offsetTCPChecksum    = 16
)

// updateV6PacketChecksums updates the checksums in the packet buffer.
// p is modified in place.
// If p.IPProto is unknown, no checksums are updated.
func updateV6PacketChecksums(p *packet.Parsed, old, new netip.Addr) {
	if len(p.Buffer()) < minIPv6Header {
		// Not enough space for an IPv6 header.
		return
	}
	o6, n6 := old.As16(), new.As16()

	// Now update the transport layer checksums, where applicable.
	tr := p.Transport()
	switch p.IPProto {
	case ipproto.ICMPv6:
		if len(tr) < minICMPv6Size {
			return
		}

		ss := tr[offsetICMPv6Checksum:]
		xsum := binary.BigEndian.Uint16(ss)
		binary.BigEndian.PutUint16(ss,
			^checksumUpdate2ByteAlignedAddress(^xsum, o6, n6))

	case ipproto.UDP, ipproto.DCCP:
		if len(tr) < minUDPSize {
			return
		}
		ss := tr[offsetUDPChecksum:]
		xsum := binary.BigEndian.Uint16(ss)
		xsum = ^xsum
		xsum = checksumUpdate2ByteAlignedAddress(xsum, o6, n6)
		xsum = ^xsum
		binary.BigEndian.PutUint16(ss, xsum)
	case ipproto.TCP:
		if len(tr) < minTCPSize {
			return
		}
		ss := tr[offsetTCPChecksum:]
		xsum := binary.BigEndian.Uint16(ss)
		xsum = ^xsum
		xsum = checksumUpdate2ByteAlignedAddress(xsum, o6, n6)
		xsum = ^xsum
		binary.BigEndian.PutUint16(ss, xsum)
	case ipproto.SCTP:
		// No transport layer update required.
	}
}

// updateV4Checksum calculates and updates the checksum in the packet buffer for
// a change between old and new. The oldSum must point to the 16-bit checksum
// field in the packet buffer that holds the old checksum value, it will be
// updated in place.
//
// The old and new must be the same length, and must be an even number of bytes.
func updateV4Checksum(oldSum, old, new []byte) {
	if len(old) != len(new) {
		panic("old and new must be the same length")
	}
	if len(old)%2 != 0 {
		panic("old and new must be of even length")
	}
	/*
		RFC 1624
		Given the following notation:

		    HC  - old checksum in header
		    C   - one's complement sum of old header
		    HC' - new checksum in header
		    C'  - one's complement sum of new header
		    m   - old value of a 16-bit field
		    m'  - new value of a 16-bit field

		    HC' = ~(C + (-m) + m')  --    [Eqn. 3]
		    HC' = ~(~HC + ~m + m')

		This can be simplified to:
		    HC' = ~(C + ~m + m')    --    [Eqn. 3]
		    HC' = ~C'
		    C'  = C + ~m + m'
	*/

	c := uint32(^binary.BigEndian.Uint16(oldSum))

	cPrime := c
	for len(new) > 0 {
		mNot := uint32(^binary.BigEndian.Uint16(old[:2]))
		mPrime := uint32(binary.BigEndian.Uint16(new[:2]))
		cPrime += mPrime + mNot
		new, old = new[2:], old[2:]
	}

	// Account for overflows by adding the carry bits back into the sum.
	for (cPrime >> 16) > 0 {
		cPrime = cPrime&0xFFFF + cPrime>>16
	}
	hcPrime := ^uint16(cPrime)
	binary.BigEndian.PutUint16(oldSum, hcPrime)
}

// checksumUpdate2ByteAlignedAddress updates an address in a calculated
// checksum.
//
// The addresses must have the same length and must contain an even number
// of bytes. The address MUST begin at a 2-byte boundary in the original buffer.
//
// This implementation is copied from gVisor, but updated to use [16]byte.
func checksumUpdate2ByteAlignedAddress(xsum uint16, old, new [16]byte) uint16 {
	const uint16Bytes = 2

	oldAddr := old[:]
	newAddr := new[:]

	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	for len(oldAddr) != 0 {
		// Convert the 2 byte sequences to uint16 values then apply the increment
		// update.
		xsum = checksumUpdate2ByteAlignedUint16(xsum, (uint16(oldAddr[0])<<8)+uint16(oldAddr[1]), (uint16(newAddr[0])<<8)+uint16(newAddr[1]))
		oldAddr = oldAddr[uint16Bytes:]
		newAddr = newAddr[uint16Bytes:]
	}

	return xsum
}

// checksumUpdate2ByteAlignedUint16 updates a uint16 value in a calculated
// checksum.
//
// The value MUST begin at a 2-byte boundary in the original buffer.
//
// This implementation is copied from gVisor.
func checksumUpdate2ByteAlignedUint16(xsum, old, new uint16) uint16 {
	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	if old == new {
		return xsum
	}
	return checksumCombine(xsum, checksumCombine(new, ^old))
}

// checksumCombine combines the two uint16 to form their checksum. This is done
// by adding them and the carry.
//
// Note that checksum a must have been computed on an even number of bytes.
//
// This implementation is copied from gVisor.
func checksumCombine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}
