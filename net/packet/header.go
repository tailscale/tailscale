// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"errors"
	"math"
)

const tcpHeaderLength = 20

// maxPacketLength is the largest length that all headers support.
// IPv4 headers using uint16 for this forces an upper bound of 64KB.
const maxPacketLength = math.MaxUint16

var (
	errSmallBuffer = errors.New("buffer too small")
	errLargePacket = errors.New("packet too large")
)

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
func Generate(h Header, payload []byte) []byte {
	hlen := h.Len()
	buf := make([]byte, hlen+len(payload))

	copy(buf[hlen:], payload)
	h.Marshal(buf)

	return buf
}
