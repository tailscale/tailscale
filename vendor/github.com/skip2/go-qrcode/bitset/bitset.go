// go-qrcode
// Copyright 2014 Tom Harwood

// Package bitset implements an append only bit array.
//
// To create a Bitset and append some bits:
//	                                  // Bitset Contents
//	b := bitset.New()                 // {}
//	b.AppendBools(true, true, false)  // {1, 1, 0}
//	b.AppendBools(true)               // {1, 1, 0, 1}
//	b.AppendValue(0x02, 4)            // {1, 1, 0, 1, 0, 0, 1, 0}
//
// To read values:
//
//	len := b.Len()                    // 8
//	v := b.At(0)                      // 1
//	v = b.At(1)                       // 1
//	v = b.At(2)                       // 0
//	v = b.At(8)                       // 0
package bitset

import (
	"bytes"
	"fmt"
	"log"
)

const (
	b0 = false
	b1 = true
)

// Bitset stores an array of bits.
type Bitset struct {
	// The number of bits stored.
	numBits int

	// Storage for individual bits.
	bits []byte
}

// New returns an initialised Bitset with optional initial bits v.
func New(v ...bool) *Bitset {
	b := &Bitset{numBits: 0, bits: make([]byte, 0)}
	b.AppendBools(v...)

	return b
}

// Clone returns a copy.
func Clone(from *Bitset) *Bitset {
	return &Bitset{numBits: from.numBits, bits: from.bits[:]}
}

// Substr returns a substring, consisting of the bits from indexes start to end.
func (b *Bitset) Substr(start int, end int) *Bitset {
	if start > end || end > b.numBits {
		log.Panicf("Out of range start=%d end=%d numBits=%d", start, end, b.numBits)
	}

	result := New()
	result.ensureCapacity(end - start)

	for i := start; i < end; i++ {
		if b.At(i) {
			result.bits[result.numBits/8] |= 0x80 >> uint(result.numBits%8)
		}
		result.numBits++
	}

	return result
}

// NewFromBase2String constructs and returns a Bitset from a string. The string
// consists of '1', '0' or ' ' characters, e.g. "1010 0101". The '1' and '0'
// characters represent true/false bits respectively, and ' ' characters are
// ignored.
//
// The function panics if the input string contains other characters.
func NewFromBase2String(b2string string) *Bitset {
	b := &Bitset{numBits: 0, bits: make([]byte, 0)}

	for _, c := range b2string {
		switch c {
		case '1':
			b.AppendBools(true)
		case '0':
			b.AppendBools(false)
		case ' ':
		default:
			log.Panicf("Invalid char %c in NewFromBase2String", c)
		}
	}

	return b
}

// AppendBytes appends a list of whole bytes.
func (b *Bitset) AppendBytes(data []byte) {
	for _, d := range data {
		b.AppendByte(d, 8)
	}
}

// AppendByte appends the numBits least significant bits from value.
func (b *Bitset) AppendByte(value byte, numBits int) {
	b.ensureCapacity(numBits)

	if numBits > 8 {
		log.Panicf("numBits %d out of range 0-8", numBits)
	}

	for i := numBits - 1; i >= 0; i-- {
		if value&(1<<uint(i)) != 0 {
			b.bits[b.numBits/8] |= 0x80 >> uint(b.numBits%8)
		}

		b.numBits++
	}
}

// AppendUint32 appends the numBits least significant bits from value.
func (b *Bitset) AppendUint32(value uint32, numBits int) {
	b.ensureCapacity(numBits)

	if numBits > 32 {
		log.Panicf("numBits %d out of range 0-32", numBits)
	}

	for i := numBits - 1; i >= 0; i-- {
		if value&(1<<uint(i)) != 0 {
			b.bits[b.numBits/8] |= 0x80 >> uint(b.numBits%8)
		}

		b.numBits++
	}
}

// ensureCapacity ensures the Bitset can store an additional |numBits|.
//
// The underlying array is expanded if necessary. To prevent frequent
// reallocation, expanding the underlying array at least doubles its capacity.
func (b *Bitset) ensureCapacity(numBits int) {
	numBits += b.numBits

	newNumBytes := numBits / 8
	if numBits%8 != 0 {
		newNumBytes++
	}

	if len(b.bits) >= newNumBytes {
		return
	}

	b.bits = append(b.bits, make([]byte, newNumBytes+2*len(b.bits))...)
}

// Append bits copied from |other|.
//
// The new length is b.Len() + other.Len().
func (b *Bitset) Append(other *Bitset) {
	b.ensureCapacity(other.numBits)

	for i := 0; i < other.numBits; i++ {
		if other.At(i) {
			b.bits[b.numBits/8] |= 0x80 >> uint(b.numBits%8)
		}
		b.numBits++
	}
}

// AppendBools appends bits to the Bitset.
func (b *Bitset) AppendBools(bits ...bool) {
	b.ensureCapacity(len(bits))

	for _, v := range bits {
		if v {
			b.bits[b.numBits/8] |= 0x80 >> uint(b.numBits%8)
		}
		b.numBits++
	}
}

// AppendNumBools appends num bits of value value.
func (b *Bitset) AppendNumBools(num int, value bool) {
	for i := 0; i < num; i++ {
		b.AppendBools(value)
	}
}

// String returns a human readable representation of the Bitset's contents.
func (b *Bitset) String() string {
	var bitString string
	for i := 0; i < b.numBits; i++ {
		if (i % 8) == 0 {
			bitString += " "
		}

		if (b.bits[i/8] & (0x80 >> byte(i%8))) != 0 {
			bitString += "1"
		} else {
			bitString += "0"
		}
	}

	return fmt.Sprintf("numBits=%d, bits=%s", b.numBits, bitString)
}

// Len returns the length of the Bitset in bits.
func (b *Bitset) Len() int {
	return b.numBits
}

// Bits returns the contents of the Bitset.
func (b *Bitset) Bits() []bool {
	result := make([]bool, b.numBits)

	var i int
	for i = 0; i < b.numBits; i++ {
		result[i] = (b.bits[i/8] & (0x80 >> byte(i%8))) != 0
	}

	return result
}

// At returns the value of the bit at |index|.
func (b *Bitset) At(index int) bool {
	if index >= b.numBits {
		log.Panicf("Index %d out of range", index)
	}

	return (b.bits[index/8] & (0x80 >> byte(index%8))) != 0
}

// Equals returns true if the Bitset equals other.
func (b *Bitset) Equals(other *Bitset) bool {
	if b.numBits != other.numBits {
		return false
	}

	if !bytes.Equal(b.bits[0:b.numBits/8], other.bits[0:b.numBits/8]) {
		return false
	}

	for i := 8 * (b.numBits / 8); i < b.numBits; i++ {
		a := (b.bits[i/8] & (0x80 >> byte(i%8)))
		b := (other.bits[i/8] & (0x80 >> byte(i%8)))

		if a != b {
			return false
		}
	}

	return true
}

// ByteAt returns a byte consisting of upto 8 bits starting at index.
func (b *Bitset) ByteAt(index int) byte {
	if index < 0 || index >= b.numBits {
		log.Panicf("Index %d out of range", index)
	}

	var result byte

	for i := index; i < index+8 && i < b.numBits; i++ {
		result <<= 1
		if b.At(i) {
			result |= 1
		}
	}

	return result
}
