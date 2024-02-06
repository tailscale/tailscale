// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rands

import (
	"math/bits"

	randv2 "math/rand/v2"
)

// Shuffle is like rand.Shuffle, but it does not allocate or lock any RNG state.
func Shuffle[T any](seed uint64, data []T) {
	var pcg randv2.PCG
	pcg.Seed(seed, seed)
	for i := len(data) - 1; i > 0; i-- {
		j := int(uint64n(&pcg, uint64(i+1)))
		data[i], data[j] = data[j], data[i]
	}
}

// Perm is like rand.Perm, but it is seeded on the stack and does not allocate
// or lock any RNG state.
func Perm(seed uint64, n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	Shuffle(seed, p)
	return p
}

// uint64n is the no-bounds-checks version of rand.Uint64N from the standard
// library. 32-bit optimizations have been elided.
func uint64n(pcg *randv2.PCG, n uint64) uint64 {
	if n&(n-1) == 0 { // n is power of two, can mask
		return pcg.Uint64() & (n - 1)
	}

	// Suppose we have a uint64 x uniform in the range [0,2⁶⁴)
	// and want to reduce it to the range [0,n) preserving exact uniformity.
	// We can simulate a scaling arbitrary precision x * (n/2⁶⁴) by
	// the high bits of a double-width multiply of x*n, meaning (x*n)/2⁶⁴.
	// Since there are 2⁶⁴ possible inputs x and only n possible outputs,
	// the output is necessarily biased if n does not divide 2⁶⁴.
	// In general (x*n)/2⁶⁴ = k for x*n in [k*2⁶⁴,(k+1)*2⁶⁴).
	// There are either floor(2⁶⁴/n) or ceil(2⁶⁴/n) possible products
	// in that range, depending on k.
	// But suppose we reject the sample and try again when
	// x*n is in [k*2⁶⁴, k*2⁶⁴+(2⁶⁴%n)), meaning rejecting fewer than n possible
	// outcomes out of the 2⁶⁴.
	// Now there are exactly floor(2⁶⁴/n) possible ways to produce
	// each output value k, so we've restored uniformity.
	// To get valid uint64 math, 2⁶⁴ % n = (2⁶⁴ - n) % n = -n % n,
	// so the direct implementation of this algorithm would be:
	//
	//	hi, lo := bits.Mul64(r.Uint64(), n)
	//	thresh := -n % n
	//	for lo < thresh {
	//		hi, lo = bits.Mul64(r.Uint64(), n)
	//	}
	//
	// That still leaves an expensive 64-bit division that we would rather avoid.
	// We know that thresh < n, and n is usually much less than 2⁶⁴, so we can
	// avoid the last four lines unless lo < n.
	//
	// See also:
	// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
	// https://lemire.me/blog/2016/06/30/fast-random-shuffling
	hi, lo := bits.Mul64(pcg.Uint64(), n)
	if lo < n {
		thresh := -n % n
		for lo < thresh {
			hi, lo = bits.Mul64(pcg.Uint64(), n)
		}
	}
	return hi
}
