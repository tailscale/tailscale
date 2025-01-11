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
	panic("lanscaping")
}

// UpdateDstAddr updates the destination address in the packet buffer (e.g. during
// DNAT). It also updates the checksum. Currently (2022-12-10) only TCP/UDP/ICMP
// is supported. It panics if provided with an address in a different
// family to the parsed packet.
func UpdateDstAddr(q *packet.Parsed, dst netip.Addr) {
	panic("lanscaping")
}

const (
	headerUDPMinimumSize    = 8  // header.UDPMinimumSize
	headerTCPMinimumSize    = 20 // header.TCPMinimumSize
	headerICMPv6MinimumSize = 8  // header.ICMPv6MinimumSize
)

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
		if len(tr) < headerUDPMinimumSize {
			// Not enough space for a UDP header.
			return
		}
		updateV4Checksum(tr[6:8], o4[:], n4[:])
	case ipproto.TCP:
		if len(tr) < headerTCPMinimumSize {
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

// updateV6PacketChecksums updates the checksums in the packet buffer.
// p is modified in place.
// If p.IPProto is unknown, no checksums are updated.
func updateV6PacketChecksums(p *packet.Parsed, old, new netip.Addr) {
	panic("lanscaping")
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
