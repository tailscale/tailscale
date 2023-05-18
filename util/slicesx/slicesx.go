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

// Deduplicate removes duplicate elements from the provided slice, compared as
// if using the == operator. The slice is modified and returned, similar to the
// append function.
func Deduplicate[S ~[]T, T comparable](s S) S {
	// Avoid allocs on empty slices
	if s == nil {
		return nil
	}

	var (
		ret  = s[:0]
		seen = make(map[T]bool)
	)
	for _, elem := range s {
		if seen[elem] {
			continue
		}
		seen[elem] = true
		ret = append(ret, elem)
	}

	// Zero out elements remaining at end of existing slice.
	var zero T
	for i := len(ret); i < len(s); i++ {
		s[i] = zero
	}

	return ret
}

// DeduplicateFunc is the same as Deduplicate, but uses the provided function
// to provide a key that is used for deduplication.
func DeduplicateFunc[S ~[]T, T any, K comparable](s S, fn func(T) K) S {
	// Avoid allocs on empty slices
	if s == nil {
		return nil
	}

	var (
		ret  = s[:0]
		seen = make(map[K]bool)
	)
	for _, elem := range s {
		key := fn(elem)
		if seen[key] {
			continue
		}
		seen[key] = true
		ret = append(ret, elem)
	}

	// Zero out elements remaining at end of existing slice.
	var zero T
	for i := len(ret); i < len(s); i++ {
		s[i] = zero
	}

	return ret
}
