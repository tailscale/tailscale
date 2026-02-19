// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"fmt"
	"io"

	"tailscale.com/net/packet"
)

// coalescePackets copies packets from buffs into dst until dst is full, it
// copies a packet shorter than the first, the maximum coalesced length
// or the maximum number of packets is reached, or there are no more packets.
// A zero maxCoalescedLen or maxCoalescedPackets means no limit.
//
// Each packet is copied starting at offset.
// Each copied packet is preceded by a Geneve header if geneve.VNI.IsSet().
//
// It returns the number of packets and bytes copied into dst, the packet
// size for the batch, or an error if Geneve header encoding fails.
func coalescePackets(
	dst []byte, geneve packet.GeneveHeader, buffs [][]byte,
	offset, maxCoalescedPackets, maxCoalescedBytes int,
) (packets, bytes, packetSize int, err error) {
	var header []byte
	if geneve.VNI.IsSet() {
		var geneveHeader [packet.GeneveFixedHeaderLength]byte
		if err := geneve.Encode(geneveHeader[:]); err != nil {
			return 0, 0, 0, err
		}
		header = geneveHeader[:]
	}
	if len(buffs) != 0 {
		// The first packet determines the packet size for the batch,
		// which is the size of each packet in the coalesced batch
		// except possibly the last one. If the first packet cannot fit
		// in dst, we cannot coalesce any packets.
		packetSize = len(header) + len(buffs[0]) - offset
		if packetSize > len(dst) {
			return 0, 0, 0, fmt.Errorf("%w: packet size %d exceeds dst size %d",
				io.ErrShortBuffer, packetSize, len(dst),
			)
		}
	}
	for _, buff := range buffs {
		buff = buff[offset:]
		packetLen := len(header) + len(buff)
		newBytes := bytes + packetLen
		if newBytes > len(dst) {
			break // no more space
		}
		if packetLen > packetSize {
			break // packet is too large for this batch
		}
		if bytes != 0 && maxCoalescedBytes != 0 && newBytes > maxCoalescedBytes {
			break // would exceed the maximum coalesced length
		}
		if maxCoalescedPackets != 0 && packets >= maxCoalescedPackets {
			break // would exceed the maximum number of coalesced packets
		}
		if packetLen == 0 {
			// Consume the zero-length packet if it's the first packet,
			// but never coalesce them.
			if packets == 0 {
				packets = 1
			}
			break
		}

		copy(dst[bytes:], header)
		copy(dst[bytes+len(header):], buff)

		packets++
		bytes = newBytes
		if packetLen < packetSize {
			// A smaller than packetSize packet on the tail is legal,
			// but it must end the batch.
			break
		}
	}
	return packets, bytes, packetSize, nil
}
