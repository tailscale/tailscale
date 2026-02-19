// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/net/ipv6"
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

// splitCoalescedPackets splits src into msgs, treating it as coalesced packets
// of packetSize. A packet is ignored if it does not fit in the destination buffer
// of the corresponding msg, in which case its bytes are not copied into msgs,
// but it still counts towards the packet count and bytes read from src.
// The final packet in src may be smaller than packetSize.
//
// If packetSize <= 0, it treats src as a single packet.
// A zero-length src is treated as a single zero-length packet.
//
// It returns the number of messages the caller should evaluate for nonzero len
// and the number of bytes read from src for those messages.
func splitCoalescedPackets(addr *net.UDPAddr, src []byte, packetSize int, msgs []ipv6.Message) (packets, bytes int) {
	srcLen := len(src)
	if packetSize <= 0 {
		packetSize = srcLen
	}
	for ; packets < len(msgs) && (bytes < srcLen || packets == 0); packets++ {
		packetLen := min(packetSize, srcLen-bytes) // last packet may be smaller
		if packetLen <= len(msgs[packets].Buffers[0]) {
			// TODO(nickkhyl): avoid the copy? We could transfer ownership of the underlying
			// buffer to the reader until the next read or an explicit release.
			msgs[packets].N = copy(msgs[packets].Buffers[0], src[bytes:bytes+packetLen])
		} else {
			msgs[packets].N = 0 // packet is too large; ignore it
		}
		msgs[packets].Addr = addr
		bytes += packetLen
	}
	return packets, bytes
}
