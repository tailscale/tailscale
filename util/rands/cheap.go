// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rands

import (
	exprand "golang.org/x/exp/rand"
)

// A Rand is a source of random numbers. It is extremely cheap to create and
// seed on the stack, and always uses the PCG random number generator.
type Rand struct {
	src exprand.PCGSource
}

// NewRand returns a new Rand with the given seed.
func NewRand(seed uint64) Rand {
	var r Rand
	r.Seed(seed)
	return r
}

// Seed uses the provided seed value to reinitialize the generator to a
// deterministic state.
// Seed should not be called concurrently with any other Rand method.
func (r *Rand) Seed(seed uint64) {
	r.src.Seed(seed)
}

// Uint64 returns a pseudo-random 64-bit integer as a uint64.
func (r *Rand) Uint64() uint64 { return r.src.Uint64() }

const maxUint64 = (1 << 64) - 1

// Uint64n returns, as a uint64, a pseudo-random number in [0,n).
// It is guaranteed more uniform than taking a Source value mod n
// for any n that is not a power of 2.
func (r *Rand) Uint64n(n uint64) uint64 {
	if n&(n-1) == 0 { // n is power of two, can mask
		if n == 0 {
			panic("invalid argument to Uint64n")
		}
		return r.Uint64() & (n - 1)
	}
	// If n does not divide v, to avoid bias we must not use
	// a v that is within maxUint64%n of the top of the range.
	v := r.Uint64()
	if v > maxUint64-n { // Fast check.
		ceiling := maxUint64 - maxUint64%n
		for v >= ceiling {
			v = r.Uint64()
		}
	}

	return v % n
}

// Intn returns, as an int, a non-negative pseudo-random number in [0,n).
// It panics if n <= 0.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic("invalid argument to Intn")
	}
	// TODO: Avoid some 64-bit ops to make it more efficient on 32-bit machines.
	return int(r.Uint64n(uint64(n)))
}
