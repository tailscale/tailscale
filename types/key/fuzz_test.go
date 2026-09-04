// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"slices"
	"strings"
	"testing"

	"go4.org/mem"
)

// fuzzHexPrefixes are the typed hex prefixes parseHex accepts.
var fuzzHexPrefixes = []string{nodePublicHexPrefix, nodePrivateHexPrefix, machinePublicHexPrefix}

func mustBytes(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func FuzzParseHex(f *testing.F) {
	// A valid untyped 64-char key (no prefix), from a real generated key
	nodePriv := NewNode()
	f.Add([]byte(nodePriv.UntypedHexString()))
	f.Add([]byte(nodePriv.Public().UntypedHexString()))
	// Typed keys, round-tripped through MarshalText
	f.Add(mustBytes(nodePriv.Public().MarshalText()))
	f.Add(mustBytes(nodePriv.MarshalText()))
	// A typed key with uppercase hex; parseHex must be case-insensitive
	f.Add([]byte(nodePublicHexPrefix + strings.ToUpper(strings.Repeat("ab", 32))))
	f.Add([]byte(nodePublicHexPrefix + "AaBbCcDd" + strings.Repeat("00", 28)))
	// All-zero key, as used for expired node keys
	f.Add([]byte(strings.Repeat("0", 64)))
	// All-f, the maximum key value
	f.Add([]byte(strings.Repeat("f", 64)))
	// Wrong length: too short, too long, and off-by-one
	f.Add([]byte("deadbeef"))
	f.Add([]byte(strings.Repeat("a", 63)))
	f.Add([]byte(strings.Repeat("a", 65)))
	f.Add([]byte(strings.Repeat("a", 128)))
	// Valid hex of wrong parity, so the length check passes but the final nibble dangles
	f.Add([]byte(strings.Repeat("g", 64)))
	f.Add([]byte(strings.Repeat("G", 64)))
	f.Add([]byte(nodePublicHexPrefix + strings.Repeat("z", 64)))
	// Non-ASCII bytes and NULs, as might come from a config file
	f.Add([]byte("ключ" + strings.Repeat("a", 60)))
	f.Add([]byte("\x00" + strings.Repeat("a", 63)))
	// A different type's prefix; must fail the prefix check, not panic
	f.Add([]byte(nodePrivateHexPrefix + strings.Repeat("a", 64)))
	f.Add([]byte(machinePublicHexPrefix + strings.Repeat("a", 64)))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out [32]byte
		// Untyped path, then each typed prefix
		_ = parseHex(out[:], mem.B(data), mem.B(nil))
		for _, p := range fuzzHexPrefixes {
			_ = parseHex(out[:], mem.B(data), mem.S(p))
		}
	})
}

func FuzzFromHexChar(f *testing.F) {
	// Valid digits, both cases
	f.Add([]byte("0123456789"))
	f.Add([]byte("abcdef"))
	f.Add([]byte("ABCDEF"))
	// Invalid ASCII letters and punctuation bracketing the valid ranges
	f.Add([]byte("/:G@`g{\x00\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range data {
			_, _ = fromHexChar(c)
		}
	})
}

func FuzzNodePublicUnmarshalBinary(f *testing.F) {
	// A valid binary node public key: "np" prefix + 32 raw bytes from a generated key
	nodePub := NewNode().Public()
	f.Add(mustBytes(nodePub.MarshalBinary()))
	// Valid prefix with all-zero and all-0xff raw bytes
	f.Add(slices.Concat([]byte(nodePublicBinaryPrefix), make([]byte, 32)))
	f.Add(slices.Concat([]byte(nodePublicBinaryPrefix), []byte(strings.Repeat("\xff", 32))))
	// Wrong prefix: hex text, or the machine key's prefixes
	f.Add([]byte("nodekey:"))
	f.Add([]byte("np"))
	f.Add([]byte("pn" + strings.Repeat("a", 32)))
	// Right prefix, wrong length: one short, one long
	f.Add(slices.Concat([]byte(nodePublicBinaryPrefix), make([]byte, 31)))
	f.Add(slices.Concat([]byte(nodePublicBinaryPrefix), make([]byte, 33)))

	f.Fuzz(func(t *testing.T, data []byte) {
		var k NodePublic
		_ = k.UnmarshalBinary(data)
	})
}

func FuzzOpen(f *testing.F) {
	nodePriv := NewNode()
	nodePub := nodePriv.Public()

	machinePriv := NewMachine()
	machinePub := machinePriv.Public()

	discoPriv := NewDisco()
	discoShared := discoPriv.Shared(discoPriv.Public())

	// Lengths just below, at, and just above the 24-byte nonce split
	f.Add(make([]byte, 23))
	f.Add(make([]byte, 24)) // nonce only, zero-length box
	f.Add(make([]byte, 25)) // nonce + single boxed byte

	// Valid sealed boxes so the Open paths are reached
	f.Add(nodePriv.SealTo(nodePub, []byte("hello")))
	f.Add(machinePriv.SealTo(machinePub, []byte("world")))
	f.Add(discoShared.Seal([]byte("disco")))
	// Boxes sealing larger payloads, so the Poly1305 tag is further from
	// the nonce and corruptions land in message bytes.
	f.Add(nodePriv.SealTo(nodePub, []byte(strings.Repeat("x", 1024))))
	f.Add(discoShared.Seal([]byte(strings.Repeat("y", 4096))))

	// Near-valid boxes: one-bit corruptions reach the box.Open verify path
	// rather than failing early on the nonce split.
	corruptBit := func(ct []byte, i int) []byte {
		bad := slices.Clone(ct)
		bad[i] ^= 0x01
		return bad
	}
	nodeCT := nodePriv.SealTo(nodePub, []byte("hello"))
	f.Add(corruptBit(nodeCT, 0))              // first nonce byte
	f.Add(corruptBit(nodeCT, 23))             // last nonce byte
	f.Add(corruptBit(nodeCT, 25))             // first ciphertext byte
	f.Add(corruptBit(nodeCT, len(nodeCT)-1))  // last ciphertext byte
	f.Add(corruptBit(nodeCT, len(nodeCT)-33)) // first tag byte
	discoCT := discoShared.Seal([]byte("disco"))
	f.Add(corruptBit(discoCT, len(discoCT)-1))
	machineCT := machinePriv.SealTo(machinePub, []byte("world"))
	f.Add(corruptBit(machineCT, len(machineCT)-1))
	// Truncations of a valid box: keep the nonce, cut the ciphertext
	// (invalid tag position) or cut into the nonce itself.
	f.Add(nodeCT[:24])
	f.Add(nodeCT[:25])
	f.Add(nodeCT[:len(nodeCT)-1])
	// A valid box for one key pair opened with the other peer's public
	// key: wrong shared secret, reaches crypto with a full-length box.
	f.Add(nodePriv.SealTo(nodePub, []byte("cross")))

	f.Fuzz(func(t *testing.T, data []byte) {
		nodePriv.OpenFrom(nodePub, data)
		machinePriv.OpenFrom(machinePub, data)
		discoShared.Open(data)
	})
}
