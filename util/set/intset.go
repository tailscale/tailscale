// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import (
	"iter"
	"maps"
	"math/bits"
	"math/rand/v2"

	"golang.org/x/exp/constraints"
	"tailscale.com/util/mak"
)

// IntSet is a set optimized for integer values close to zero
// or set of integers that are close in value.
type IntSet[T constraints.Integer] struct {
	// bits is a [bitSet] for numbers less than [bits.UintSize].
	bits bitSet

	// extra is a mapping of [bitSet] for numbers not in bits,
	// where the key is a number modulo [bits.UintSize].
	extra map[uint64]bitSet

	// extraLen is the count of numbers in extra since len(extra)
	// does not reflect that each bitSet may have multiple numbers.
	extraLen int
}

// IntsOf constructs an [IntSet] with the provided elements.
func IntsOf[T constraints.Integer](slice ...T) IntSet[T] {
	var s IntSet[T]
	for _, e := range slice {
		s.Add(e)
	}
	return s
}

// Values returns an iterator over the elements of the set.
// The iterator will yield the elements in no particular order.
func (s IntSet[T]) Values() iter.Seq[T] {
	return func(yield func(T) bool) {
		if s.bits != 0 {
			for i := range s.bits.values() {
				if !yield(decodeZigZag[T](i)) {
					return
				}
			}
		}
		if s.extra != nil {
			for hi, bs := range s.extra {
				for lo := range bs.values() {
					if !yield(decodeZigZag[T](hi*bits.UintSize + lo)) {
						return
					}
				}
			}
		}
	}
}

// Contains reports whether e is in the set.
func (s IntSet[T]) Contains(e T) bool {
	if v := encodeZigZag(e); v < bits.UintSize {
		return s.bits.contains(v)
	} else {
		hi, lo := v/uint64(bits.UintSize), v%uint64(bits.UintSize)
		return s.extra[hi].contains(lo)
	}
}

// Add adds e to the set.
//
// When storing a IntSet in a map as a value type,
// it is important to re-assign the map entry after calling Add or Delete,
// as the IntSet's representation may change.
func (s *IntSet[T]) Add(e T) {
	if v := encodeZigZag(e); v < bits.UintSize {
		s.bits.add(v)
	} else {
		hi, lo := v/uint64(bits.UintSize), v%uint64(bits.UintSize)
		if bs := s.extra[hi]; !bs.contains(lo) {
			bs.add(lo)
			mak.Set(&s.extra, hi, bs)
			s.extra[hi] = bs
			s.extraLen++
		}
	}
}

// AddSeq adds the values from seq to the set.
func (s *IntSet[T]) AddSeq(seq iter.Seq[T]) {
	for e := range seq {
		s.Add(e)
	}
}

// Len reports the number of elements in the set.
func (s IntSet[T]) Len() int {
	return s.bits.len() + s.extraLen
}

// Delete removes e from the set.
//
// When storing a IntSet in a map as a value type,
// it is important to re-assign the map entry after calling Add or Delete,
// as the IntSet's representation may change.
func (s *IntSet[T]) Delete(e T) {
	if v := encodeZigZag(e); v < bits.UintSize {
		s.bits.delete(v)
	} else {
		hi, lo := v/uint64(bits.UintSize), v%uint64(bits.UintSize)
		if bs := s.extra[hi]; bs.contains(lo) {
			bs.delete(lo)
			mak.Set(&s.extra, hi, bs)
			s.extra[hi] = bs
			s.extraLen--
		}
	}
}

// DeleteSeq deletes the values in seq from the set.
func (s *IntSet[T]) DeleteSeq(seq iter.Seq[T]) {
	for e := range seq {
		s.Delete(e)
	}
}

// Equal reports whether s is equal to other.
func (s IntSet[T]) Equal(other IntSet[T]) bool {
	for hi, bits := range s.extra {
		if other.extra[hi] != bits {
			return false
		}
	}
	return s.extraLen == other.extraLen && s.bits == other.bits
}

// Clone returns a copy of s that doesn't alias the original.
func (s IntSet[T]) Clone() IntSet[T] {
	return IntSet[T]{
		bits:     s.bits,
		extra:    maps.Clone(s.extra),
		extraLen: s.extraLen,
	}
}

type bitSet uint

func (s bitSet) values() iter.Seq[uint64] {
	return func(yield func(uint64) bool) {
		// Hyrum-proofing: randomly iterate in forwards or reverse.
		if rand.Uint64()%2 == 0 {
			for i := 0; i < bits.UintSize; i++ {
				if s.contains(uint64(i)) && !yield(uint64(i)) {
					return
				}
			}
		} else {
			for i := bits.UintSize; i >= 0; i-- {
				if s.contains(uint64(i)) && !yield(uint64(i)) {
					return
				}
			}
		}
	}
}
func (s bitSet) len() int               { return bits.OnesCount(uint(s)) }
func (s bitSet) contains(i uint64) bool { return s&(1<<i) > 0 }
func (s *bitSet) add(i uint64)          { *s |= 1 << i }
func (s *bitSet) delete(i uint64)       { *s &= ^(1 << i) }

// encodeZigZag encodes an integer as an unsigned integer ensuring that
// negative integers near zero still have a near zero positive value.
// For unsigned integers, it returns the value verbatim.
func encodeZigZag[T constraints.Integer](v T) uint64 {
	var zero T
	if ^zero >= 0 { // must be constraints.Unsigned
		return uint64(v)
	} else { // must be constraints.Signed
		// See [google.golang.org/protobuf/encoding/protowire.EncodeZigZag]
		return uint64(int64(v)<<1) ^ uint64(int64(v)>>63)
	}
}

// decodeZigZag decodes an unsigned integer as an integer ensuring that
// negative integers near zero still have a near zero positive value.
// For unsigned integers, it returns the value verbatim.
func decodeZigZag[T constraints.Integer](v uint64) T {
	var zero T
	if ^zero >= 0 { // must be constraints.Unsigned
		return T(v)
	} else { // must be constraints.Signed
		// See [google.golang.org/protobuf/encoding/protowire.DecodeZigZag]
		return T(int64(v>>1) ^ int64(v)<<63>>63)
	}
}
