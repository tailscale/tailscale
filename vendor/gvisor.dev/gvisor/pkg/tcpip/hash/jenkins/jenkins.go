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

// Package jenkins implements Jenkins's one_at_a_time, non-cryptographic hash
// functions created by by Bob Jenkins.
//
// See https://en.wikipedia.org/wiki/Jenkins_hash_function#cite_note-dobbsx-1
//
package jenkins

import (
	"hash"
)

// Sum32 represents Jenkins's one_at_a_time hash.
//
// Use the Sum32 type directly (as opposed to New32 below)
// to avoid allocations.
type Sum32 uint32

// New32 returns a new 32-bit Jenkins's one_at_a_time hash.Hash.
//
// Its Sum method will lay the value out in big-endian byte order.
func New32() hash.Hash32 {
	var s Sum32
	return &s
}

// Reset resets the hash to its initial state.
func (s *Sum32) Reset() { *s = 0 }

// Sum32 returns the hash value
func (s *Sum32) Sum32() uint32 {
	sCopy := *s

	sCopy += sCopy << 3
	sCopy ^= sCopy >> 11
	sCopy += sCopy << 15

	return uint32(sCopy)
}

// Write adds more data to the running hash.
//
// It never returns an error.
func (s *Sum32) Write(data []byte) (int, error) {
	sCopy := *s
	for _, b := range data {
		sCopy += Sum32(b)
		sCopy += sCopy << 10
		sCopy ^= sCopy >> 6
	}
	*s = sCopy
	return len(data), nil
}

// Size returns the number of bytes Sum will return.
func (s *Sum32) Size() int { return 4 }

// BlockSize returns the hash's underlying block size.
func (s *Sum32) BlockSize() int { return 1 }

// Sum appends the current hash to in and returns the resulting slice.
//
// It does not change the underlying hash state.
func (s *Sum32) Sum(in []byte) []byte {
	v := s.Sum32()
	return append(in, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
