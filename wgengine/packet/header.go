// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

// Header is a packet header capable of marshaling itself into a byte buffer.
type Header interface {
	// Len returns the length of the header after marshaling.
	Len() int
	// Marshal serializes the header into buf in wire format.
	// It clobbers the header region, which is the first h.Length() bytes of buf.
	// It explicitly initializes every byte of the header region,
	// so pre-zeroing it on reuse is not required. It does not allocate memory.
	// It fails if and only if len(buf) < Length().
	Marshal(buf []byte) error
	// ToResponse transforms the header into one for a response packet.
	// For instance, this swaps the source and destination IPs.
	ToResponse()
}

// Generate generates a new packet with the given header and payload.
// Unlike Header.Marshal, this does allocate memory.
func Generate(header Header, payload []byte) []byte {
	headerLength := header.Len()
	packetLength := headerLength + len(payload)
	buf := make([]byte, packetLength)

	copy(buf[headerLength:], payload)
	header.Marshal(buf)

	return buf
}
