// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func FuzzNextSize(f *testing.F) {
	// Valid frames from the package's own encoder, as a baseline the parser must size exactly
	frame := AppendEncode(nil, []byte("hello world, hello zstd"))
	f.Add(frame)
	// Empty input: zero-frame encoding of nil
	f.Add(AppendEncode(nil, nil))
	// Larger input, more likely to produce a compressed block followed by checksummed content
	f.Add(AppendEncode(nil, []byte(strings.Repeat("the quick brown fox ", 512))))
	// Two concatenated frames; NextSize must size the first, not the pair
	f.Add(slices.Concat(frame, frame))
	// Valid frame with a second frame truncated right after it
	f.Add(slices.Concat(frame, []byte{0x28, 0xb5}))
	// Bad or truncated magic
	f.Add(make([]byte, 3))
	f.Add([]byte{0x28, 0xb5, 0x2f})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfe}) // one wrong magic byte
	f.Add([]byte{0x00, 0xb5, 0x2f, 0xfd}) // wrong in first byte only
	// Data frame magic alone; no FHD byte follows
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd})
	// Skippable frames: no size field, valid size, oversized size, and truncated payload
	f.Add([]byte{0x50, 0x2a, 0x4d, 0x18}) // missing size
	f.Add([]byte{0x50, 0x2a, 0x4d, 0x18, 0x08, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0x5f, 0x2a, 0x4d, 0x18, 0xff, 0xff, 0xff, 0xff})    // max size, empty payload
	f.Add([]byte{0x50, 0x2a, 0x4d, 0x18, 0x04, 0x00, 0x00, 0x00, 1}) // size 4, 1 byte present
	f.Add([]byte{0x50, 0x2a, 0x4d, 0x18, 0x00, 0x00})                // size field itself cut off
	// Frame header malformations
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x08})       // reserved FHD bit set
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x01})       // dictionary ID (1 byte) missing
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x02})       // dictionary ID (2 bytes) missing
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x03})       // dictionary ID (4 bytes) missing
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x40, 0x00}) // window byte present, 2-byte FCS missing
	// Single-segment FHD 0x20 requires a 1-byte FCS; cut inside it
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x20})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x80, 0x04, 0x00})       // 4-byte FCS truncated
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0xc0, 0x00, 0x01, 0x02}) // 8-byte FCS truncated
	// Header complete, block header missing
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05, 0x20})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05, 0x20, 0x00}) // 2 of 3 bytes
	// Block header malformations behind a complete multi-block frame header
	// Raw block (type 0), not last, size 2; then a second header with reserved block type 3
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05,
		0x10, 0x00, 0x00, 1, 2, // raw block, not last, size 2
		0x0e, 0x00, 0x00, 0xff}) // reserved block type, size 1
	// Raw block claiming more content than present
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05, 0x20, 0xff, 0x7f, 1, 2, 3})
	// Not-last block with zero content, then truncated second header
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05, 0x00, 0x00, 0x00})
	// Compressed block (type 2), not last, size 2; content too short for the next header
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x05, 0x14, 0x00, 0x00, 1, 2})
	// Last RLE block (type 1), checksum flag set, no checksum bytes present
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x05, 0x23, 0x00, 0x00, 0xff})
	// RLE block, last, content present, but checksum cut short
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x05, 0x23, 0x00, 0x00, 0xff, 0x12, 0x34})
	// Multi-block frame with a final checksum, complete and valid: two raw blocks plus 4 checksum bytes
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x05,
		0x10, 0x00, 0x00, 1, 2, // raw block, not last, size 2
		0x09, 0x00, 0x00, 3, // raw block, last, size 1
		0xde, 0xad, 0xbe, 0xef}) // checksum

	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := NextSize(data)
		switch {
		case err == nil:
			if n < 0 || n > len(data) {
				t.Fatalf("NextSize(%x) = %d, nil; want 0 <= n <= len(data)", data, n)
			}
		case errors.Is(err, io.ErrUnexpectedEOF),
			errors.Is(err, zstd.ErrMagicMismatch),
			// unexported error zstd.Header.Decode returns for a reserved frame header bit
			err.Error() == "reserved bit set on frame header":
			// Documented errors
		default:
			t.Fatalf("NextSize(%x) = %d, %v; want nil or a documented error", data, n, err)
		}
	})
}
