// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hash contains utility functions for hashing.
package hash

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var hashIV = RandN32(1)[0]

// RandN32 generates a slice of n cryptographic random 32-bit numbers.
func RandN32(n int) []uint32 {
	b := make([]byte, 4*n)
	if _, err := rand.Read(b); err != nil {
		panic("unable to get random numbers: " + err.Error())
	}
	r := make([]uint32, n)
	for i := range r {
		r[i] = binary.LittleEndian.Uint32(b[4*i : (4*i + 4)])
	}
	return r
}

// Hash3Words calculates the Jenkins hash of 3 32-bit words. This is adapted
// from linux.
func Hash3Words(a, b, c, initval uint32) uint32 {
	const iv = 0xdeadbeef + (3 << 2)
	initval += iv

	a += initval
	b += initval
	c += initval

	c ^= b
	c -= rol32(b, 14)
	a ^= c
	a -= rol32(c, 11)
	b ^= a
	b -= rol32(a, 25)
	c ^= b
	c -= rol32(b, 16)
	a ^= c
	a -= rol32(c, 4)
	b ^= a
	b -= rol32(a, 14)
	c ^= b
	c -= rol32(b, 24)

	return c
}

// IPv4FragmentHash computes the hash of the IPv4 fragment as suggested in RFC 791.
func IPv4FragmentHash(h header.IPv4) uint32 {
	x := uint32(h.ID())<<16 | uint32(h.Protocol())
	t := h.SourceAddress()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(x, y, z, hashIV)
}

// IPv6FragmentHash computes the hash of the ipv6 fragment.
// Unlike IPv4, the protocol is not used to compute the hash.
// RFC 2640 (sec 4.5) is not very sharp on this aspect.
// As a reference, also Linux ignores the protocol to compute
// the hash (inet6_hash_frag).
func IPv6FragmentHash(h header.IPv6, id uint32) uint32 {
	t := h.SourceAddress()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(id, y, z, hashIV)
}

func rol32(v, shift uint32) uint32 {
	return (v << shift) | (v >> ((-shift) & 31))
}
