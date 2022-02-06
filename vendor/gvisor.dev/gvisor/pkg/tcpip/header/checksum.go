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

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package header

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// ChecksumSize is the size of a checksum.
//
// The checksum is held in a uint16 which is 2 bytes.
const ChecksumSize = 2

// PutChecksum puts the checksum in the provided byte slice.
func PutChecksum(b []byte, xsum uint16) {
	binary.BigEndian.PutUint16(b, xsum)
}

func calculateChecksum(buf []byte, odd bool, initial uint32) (uint16, bool) {
	v := initial

	if odd {
		v += uint32(buf[0])
		buf = buf[1:]
	}

	l := len(buf)
	odd = l&1 != 0
	if odd {
		l--
		v += uint32(buf[l]) << 8
	}

	for i := 0; i < l; i += 2 {
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
	}

	return ChecksumCombine(uint16(v), uint16(v>>16)), odd
}

func unrolledCalculateChecksum(buf []byte, odd bool, initial uint32) (uint16, bool) {
	v := initial

	if odd {
		v += uint32(buf[0])
		buf = buf[1:]
	}

	l := len(buf)
	odd = l&1 != 0
	if odd {
		l--
		v += uint32(buf[l]) << 8
	}
	for (l - 64) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[64:]
		l = l - 64
	}
	if (l - 32) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[32:]
		l = l - 32
	}
	if (l - 16) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[16:]
		l = l - 16
	}
	if (l - 8) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		buf = buf[8:]
		l = l - 8
	}
	if (l - 4) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		buf = buf[4:]
		l = l - 4
	}

	// At this point since l was even before we started unrolling
	// there can be only two bytes left to add.
	if l != 0 {
		v += (uint32(buf[0]) << 8) + uint32(buf[1])
	}

	return ChecksumCombine(uint16(v), uint16(v>>16)), odd
}

// ChecksumOld calculates the checksum (as defined in RFC 1071) of the bytes in
// the given byte array. This function uses a non-optimized implementation. Its
// only retained for reference and to use as a benchmark/test. Most code should
// use the header.Checksum function.
//
// The initial checksum must have been computed on an even number of bytes.
func ChecksumOld(buf []byte, initial uint16) uint16 {
	s, _ := calculateChecksum(buf, false, uint32(initial))
	return s
}

// Checksum calculates the checksum (as defined in RFC 1071) of the bytes in the
// given byte array. This function uses an optimized unrolled version of the
// checksum algorithm.
//
// The initial checksum must have been computed on an even number of bytes.
func Checksum(buf []byte, initial uint16) uint16 {
	s, _ := unrolledCalculateChecksum(buf, false, uint32(initial))
	return s
}

// ChecksumVV calculates the checksum (as defined in RFC 1071) of the bytes in
// the given VectorizedView.
//
// The initial checksum must have been computed on an even number of bytes.
func ChecksumVV(vv buffer.VectorisedView, initial uint16) uint16 {
	var c Checksumer
	for _, v := range vv.Views() {
		c.Add([]byte(v))
	}
	return ChecksumCombine(initial, c.Checksum())
}

// Checksumer calculates checksum defined in RFC 1071.
type Checksumer struct {
	sum uint16
	odd bool
}

// Add adds b to checksum.
func (c *Checksumer) Add(b []byte) {
	if len(b) > 0 {
		c.sum, c.odd = unrolledCalculateChecksum(b, c.odd, uint32(c.sum))
	}
}

// Checksum returns the latest checksum value.
func (c *Checksumer) Checksum() uint16 {
	return c.sum
}

// ChecksumCombine combines the two uint16 to form their checksum. This is done
// by adding them and the carry.
//
// Note that checksum a must have been computed on an even number of bytes.
func ChecksumCombine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}

// PseudoHeaderChecksum calculates the pseudo-header checksum for the given
// destination protocol and network address. Pseudo-headers are needed by
// transport layers when calculating their own checksum.
func PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, srcAddr tcpip.Address, dstAddr tcpip.Address, totalLen uint16) uint16 {
	xsum := Checksum([]byte(srcAddr), 0)
	xsum = Checksum([]byte(dstAddr), xsum)

	// Add the length portion of the checksum to the pseudo-checksum.
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	xsum = Checksum(tmp, xsum)

	return Checksum([]byte{0, uint8(protocol)}, xsum)
}

// checksumUpdate2ByteAlignedUint16 updates a uint16 value in a calculated
// checksum.
//
// The value MUST begin at a 2-byte boundary in the original buffer.
func checksumUpdate2ByteAlignedUint16(xsum, old, new uint16) uint16 {
	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	return ChecksumCombine(xsum, ChecksumCombine(new, ^old))
}

// checksumUpdate2ByteAlignedAddress updates an address in a calculated
// checksum.
//
// The addresses must have the same length and must contain an even number
// of bytes. The address MUST begin at a 2-byte boundary in the original buffer.
func checksumUpdate2ByteAlignedAddress(xsum uint16, old, new tcpip.Address) uint16 {
	const uint16Bytes = 2

	if len(old) != len(new) {
		panic(fmt.Sprintf("buffer lengths are different; old = %d, new = %d", len(old), len(new)))
	}

	if len(old)%uint16Bytes != 0 {
		panic(fmt.Sprintf("buffer has an odd number of bytes; got = %d", len(old)))
	}

	// As per RFC 1071 page 4,
	//	(4)  Incremental Update
	//
	//        ...
	//
	//        To update the checksum, simply add the differences of the
	//        sixteen bit integers that have been changed.  To see why this
	//        works, observe that every 16-bit integer has an additive inverse
	//        and that addition is associative.  From this it follows that
	//        given the original value m, the new value m', and the old
	//        checksum C, the new checksum C' is:
	//
	//                C' = C + (-m) + m' = C + (m' - m)
	for len(old) != 0 {
		// Convert the 2 byte sequences to uint16 values then apply the increment
		// update.
		xsum = checksumUpdate2ByteAlignedUint16(xsum, (uint16(old[0])<<8)+uint16(old[1]), (uint16(new[0])<<8)+uint16(new[1]))
		old = old[uint16Bytes:]
		new = new[uint16Bytes:]
	}

	return xsum
}
