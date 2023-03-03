// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package slicesx contains some helpful generic slice functions.
package slicesx

import "math/rand"

// Interleave combines two slices of the form [a, b, c] and [x, y, z] into a
// slice with elements interleaved; i.e. [a, x, b, y, c, z].
func Interleave[S ~[]T, T any](a, b S) S {
	// Avoid allocating an empty slice.
	if a == nil && b == nil {
		return nil
	}

	var (
		i   int
		ret = make([]T, 0, len(a)+len(b))
	)
	for i = 0; i < len(a) && i < len(b); i++ {
		ret = append(ret, a[i], b[i])
	}
	ret = append(ret, a[i:]...)
	ret = append(ret, b[i:]...)
	return ret
}

// Shuffle randomly shuffles a slice in-place, similar to rand.Shuffle.
func Shuffle[S ~[]T, T any](s S) {
	// TODO(andrew): use a pooled Rand?

	// This is the same Fisher-Yates shuffle implementation as rand.Shuffle
	n := len(s)
	i := n - 1
	for ; i > 1<<31-1-1; i-- {
		j := int(rand.Int63n(int64(i + 1)))
		s[i], s[j] = s[j], s[i]
	}
	for ; i > 0; i-- {
		j := int(rand.Int31n(int32(i + 1)))
		s[i], s[j] = s[j], s[i]
	}
}
