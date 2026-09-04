// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import "testing"

func FuzzParsePCPResponse(f *testing.F) {
	// Minimal valid 24-byte PCP common header
	f.Add([]byte{2, 129, 0, 7, 28, 32, 155, 237, 10, 188, 17, 255, 135, 180, 175, 246})
	// Response with the opcode reply bit set and an OK result code
	f.Add([]byte{2, 129, 0, 4, 210, 3, 241, 208, 251, 45, 157, 76, 10, 188, 17, 255})
	// Version mismatch / too-short inputs to exercise the length check
	f.Add([]byte{2})
	// Full 24-byte headers so the parse succeeds: a MAP opcode reply with an
	// OK result code, and an ANNOUNCE reply (opcode 0, result 0)
	f.Add([]byte{2, 129, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	f.Add([]byte{2, 0, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	// A 24-byte header with a version mismatch (b[0] != 2)
	f.Add([]byte{1, 129, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	// A 23-byte response, one short of the minimum, with a valid version
	f.Add([]byte{2, 129, 0, 0, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	// The announce-reply opcode (0x80) as consumed by portmapper.go
	f.Add([]byte{2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	// Opcode and result codes never successfully parsed by existing seeds
	f.Add([]byte{2, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{2, 0x80, 0, 12, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	f.Add([]byte{2, 129, 0, 1, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	f.Add([]byte{2, 129, 0, 0xff, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2})
	// Zero and max lifetime/epoch values
	f.Add([]byte{2, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{2, 129, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parsePCPResponse(data)
	})
}

func FuzzParsePCPMapResponse(f *testing.F) {
	f.Add(examplePCPMapResponse)
	// A 60-byte MAP response with an OK result code, so the parse succeeds
	// past the common header into the mapping fields.
	f.Add([]byte{
		2, 129, 0, 0, 0, 0, 0x1c, 0x20, // version, MAP reply, result OK, lifetime 7200
		0, 0, 0, 1, // epoch
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // client IP
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // mapping nonce
		byte(pcpUDPMapping), 0, 0, 0, // protocol + reserved
		0x04, 0xd2, // internal port
		0x12, 0x34, // external port
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // external IP
	})
	// A 60-byte response with a valid common header but a NOT_AUTHORIZED result code
	f.Add([]byte{
		2, 129, 0, 2, 0, 0, 0x1c, 0x20,
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2,
		0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	// A truncated 59-byte response, below the 60-byte minimum
	f.Add([]byte{
		2, 129, 0, 0, 0, 0, 0x1c, 0x20,
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2,
		0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})
	// A 60-byte response with an invalid common header (version 1)
	f.Add([]byte{
		1, 129, 0, 0, 0, 0, 0x1c, 0x20,
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2, 0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	// A generic non-OK result code (AddressMismatch, 12) on a valid-length response
	f.Add([]byte{
		2, 129, 0, 12, 0, 0, 0x1c, 0x20,
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2, 0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	// A 60-byte announce-reply opcode (0x80): the opcode is not validated, so this parses
	f.Add([]byte{
		2, 0x80, 0, 0, 0, 0, 0x1c, 0x20,
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2, 0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	// Zero lifetime (renewAfter == goodUntil == now) and zero epoch
	f.Add([]byte{
		2, 129, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2, 0x12, 0x34,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})
	// Max lifetime and max epoch
	f.Add([]byte{
		2, 129, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		byte(pcpUDPMapping), 0, 0, 0,
		0x04, 0xd2, 0xff, 0xff,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := parsePCPMapResponse(data)
		if err != nil {
			if m != nil {
				t.Fatalf("parsePCPMapResponse returned both a mapping and an error: %v", err)
			}
		} else if m == nil {
			t.Fatalf("parsePCPMapResponse returned neither a mapping or an error")
		}
	})
}
