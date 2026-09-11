// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"testing"
)

func FuzzFramedReader(f *testing.F) {
	const maxSize = int64(1 << 20)

	f.Add([]byte{0x08, 0x00, 1, 2})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	// A valid 4-byte little-endian frame (len 4) followed by its payload
	f.Add([]byte{0x04, 0x00, 0x00, 0x00, 'a', 'b', 'c', 'd'})
	// Two consecutive frames
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 'x', 'y', 0x01, 0x00, 0x00, 0x00, 'z'})
	// A frame length that exceeds maxSize (1<<20): 0x00100001
	f.Add([]byte{0x01, 0x00, 0x10, 0x00, 0, 0})
	// A zero-length frame, rejected by the reader
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 'a', 'b'})
	// A frame that exactly equals maxSize (1<<20) bytes
	f.Add(append([]byte{0x00, 0x00, 0x10, 0x00}, make([]byte, maxSize)...))
	// A frame one byte over maxSize
	f.Add(append([]byte{0x01, 0x00, 0x10, 0x00}, make([]byte, maxSize+1)...))
	// Empty and partial length prefixes: io.EOF and ErrUnexpectedEOF
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00, 0x00})
	// Truncated payload: header promises 4 bytes but only 2 remain (EOF mid-frame)
	f.Add([]byte{0x04, 0x00, 0x00, 0x00, 'a', 'b'})
	// Frame longer than the 8-byte read buffer, and exactly equal to it
	f.Add(append([]byte{0x10, 0x00, 0x00, 0x00}, make([]byte, 16)...))
	f.Add(append([]byte{0x08, 0x00, 0x00, 0x00}, make([]byte, 8)...))
	// Max valid size (0xfffff), one under maxSize, truncated payload
	f.Add([]byte{0xff, 0xff, 0x0f, 0x00, 'a'})
	// A valid frame followed by bad frames mid-stream
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 'a', 'b', 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 'a', 'b', 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		fr := &framedReader{
			r:       bytes.NewReader(data),
			maxSize: maxSize,
		}
		var p [8]byte
		for i := 0; i < 100; i++ {
			if _, err := fr.Read(p[:]); err != nil {
				break
			}
		}
	})
}

func FuzzBoundedReader(f *testing.F) {
	f.Add([]byte("payload"))

	f.Fuzz(func(t *testing.T, data []byte) {
		b := &boundedReader{
			r:      bytes.NewReader(data),
			max:    DefaultMaxMessageSize,
			remain: DefaultMaxMessageSize,
		}
		var p [8]byte
		for i := 0; i < 100; i++ {
			if _, err := b.Read(p[:]); err != nil {
				break
			}
		}
	})
}
