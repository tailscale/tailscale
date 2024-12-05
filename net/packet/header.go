// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"errors"
	"math"
)

const tcpHeaderLength = 20
const sctpHeaderLength = 12

// maxPacketLength is the largest length that all headers support.
// IPv4 headers using uint16 for this forces an upper bound of 64KB.
const maxPacketLength = math.MaxUint16

var (
	// errSmallBuffer is returned when Marshal receives a buffer
	// too small to contain the header to marshal.
	errSmallBuffer = errors.New("buffer too small")
	// errLargePacket is returned when Marshal receives a payload
	// larger than the maximum representable size in header
	// fields.
	errLargePacket = errors.New("packet too large")
)

// Header is a packet header capable of marshaling itself into a byte
// buffer.
type Header interface {
	// Len returns the length of the marshaled packet.
	Len() int
	// Marshal serializes the header into buf, which must be at
	// least Len() bytes long. Implementations of Marshal assume
	// that bytes after the first Len() are payload bytes for the
	// purpose of computing length and checksum fields. Marshal
	// implementations must not allocate memory.
	Marshal(buf []byte) error
}

// HeaderChecksummer is implemented by Header implementations that
// need to do a checksum over their payloads.
type HeaderChecksummer interface {
	Header

	// WriteCheck writes the correct checksum into buf, which should
	// be be the already-marshalled header and payload.
	WriteChecksum(buf []byte)
}

// Generate generates a new packet with the given Header and
// payload. This function allocates memory, see Header.Marshal for an
// allocation-free option.
func Generate(h Header, payload []byte) []byte {
	hlen := h.Len()
	buf := make([]byte, hlen+len(payload))

	copy(buf[hlen:], payload)
	h.Marshal(buf)

	if hc, ok := h.(HeaderChecksummer); ok {
		hc.WriteChecksum(buf)
	}

	return buf
}
