// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ippool

import (
	"math/big"
	"math/bits"
	"math/rand/v2"
	"net/netip"

	"go4.org/netipx"
)

func addrLessOrEqual(a, b netip.Addr) bool {
	if a.Less(b) {
		return true
	}
	if a == b {
		return true
	}
	return false
}

// indexOfAddr returns the index of addr in ipset, or -1 if not found.
func indexOfAddr(addr netip.Addr, ipset *netipx.IPSet) int {
	var base int // offset of the current range
	for _, r := range ipset.Ranges() {
		if addr.Less(r.From()) {
			return -1
		}
		numFrom := v4ToNum(r.From())
		if addrLessOrEqual(addr, r.To()) {
			numInRange := int(v4ToNum(addr) - numFrom)
			return base + numInRange
		}
		numTo := v4ToNum(r.To())
		base += int(numTo-numFrom) + 1
	}
	return -1
}

// addrAtIndex returns the address at the given index in ipset, or an empty
// address if index is out of range.
func addrAtIndex(index int, ipset *netipx.IPSet) netip.Addr {
	if index < 0 {
		return netip.Addr{}
	}
	var base int // offset of the current range
	for _, r := range ipset.Ranges() {
		numFrom := v4ToNum(r.From())
		numTo := v4ToNum(r.To())
		if index <= base+int(numTo-numFrom) {
			return numToV4(uint32(int(numFrom) + index - base))
		}
		base += int(numTo-numFrom) + 1
	}
	return netip.Addr{}
}

// TODO(golang/go#9455): once we have uint128 we can easily implement for all addrs.

// v4ToNum returns a uint32 representation of the IPv4 address. If addr is not
// an IPv4 address, this function will panic.
func v4ToNum(addr netip.Addr) uint32 {
	addr = addr.Unmap()
	if !addr.Is4() {
		panic("only IPv4 addresses are supported by v4ToNum")
	}
	b := addr.As4()
	var o uint32
	o = o<<8 | uint32(b[0])
	o = o<<8 | uint32(b[1])
	o = o<<8 | uint32(b[2])
	o = o<<8 | uint32(b[3])
	return o
}

func numToV4(i uint32) netip.Addr {
	var addr [4]byte
	addr[0] = byte((i >> 24) & 0xff)
	addr[1] = byte((i >> 16) & 0xff)
	addr[2] = byte((i >> 8) & 0xff)
	addr[3] = byte(i & 0xff)
	return netip.AddrFrom4(addr)
}

// allocAddr returns an address in ipset that is not already marked allocated in allocated.
func allocAddr(ipset *netipx.IPSet, allocated *big.Int) netip.Addr {
	// first try to allocate a random IP from each range, if we land on one.
	var base uint32 // index offset of the current range
	for _, r := range ipset.Ranges() {
		numFrom := v4ToNum(r.From())
		numTo := v4ToNum(r.To())
		randInRange := rand.N(numTo - numFrom)
		randIndex := base + randInRange
		if allocated.Bit(int(randIndex)) == 0 {
			allocated.SetBit(allocated, int(randIndex), 1)
			return numToV4(numFrom + randInRange)
		}
		base += numTo - numFrom + 1
	}

	// fall back to seeking a free bit in the allocated set
	index := -1
	for i, word := range allocated.Bits() {
		zbi := leastZeroBit(uint(word))
		if zbi == -1 {
			continue
		}
		index = i*bits.UintSize + zbi
		allocated.SetBit(allocated, index, 1)
		break
	}
	if index == -1 {
		return netip.Addr{}
	}
	return addrAtIndex(index, ipset)
}

// leastZeroBit returns the index of the least significant zero bit in the given uint, or -1
// if all bits are set.
func leastZeroBit(n uint) int {
	notN := ^n
	rightmostBit := notN & -notN
	if rightmostBit == 0 {
		return -1
	}
	return bits.TrailingZeros(rightmostBit)
}
