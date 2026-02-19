// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"math/bits"

	"golang.org/x/exp/constraints"
)

// alignUp returns the smallest value >= v that is a multiple of alignment.
// The alignment must be a power of two.
func alignUp[V, A constraints.Integer](v V, alignment A) V {
	return (v + V(alignment) - 1) &^ (V(alignment) - 1)
}

// alignUpOffset rounds offset up so that base+offset is aligned to the
// specified boundary. Alignment must be a power of two.
func alignUpOffset(base, offset, alignment uintptr) uintptr {
	return alignUp(base+offset, alignment) - base
}

// isPowerOfTwo reports whether n is a power of two.
func isPowerOfTwo[T constraints.Integer](n T) bool {
	return n > 0 && (n&(n-1)) == 0
}

// floorPowerOfTwo returns the largest power of two <= n.
func floorPowerOfTwo[T constraints.Unsigned](n T) T {
	if n == 0 {
		return 0
	}
	return 1 << (bits.Len64(uint64(n)) - 1)
}
