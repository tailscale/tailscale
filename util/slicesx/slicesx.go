// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package slicesx contains some helpful generic slice functions.
package slicesx

import (
	"math/rand/v2"
	"slices"
)

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
		j := int(rand.N(int64(i + 1)))
		s[i], s[j] = s[j], s[i]
	}
	for ; i > 0; i-- {
		j := int(rand.N(int32(i + 1)))
		s[i], s[j] = s[j], s[i]
	}
}

// Partition returns two slices, the first containing the elements of the input
// slice for which the callback evaluates to true, the second containing the rest.
//
// This function does not mutate s.
func Partition[S ~[]T, T any](s S, cb func(T) bool) (trues, falses S) {
	for _, elem := range s {
		if cb(elem) {
			trues = append(trues, elem)
		} else {
			falses = append(falses, elem)
		}
	}
	return
}

// EqualSameNil reports whether two slices are equal: the same length, same
// nilness (notably when length zero), and all elements equal. If the lengths
// are different or their nilness differs, Equal returns false. Otherwise, the
// elements are compared in increasing index order, and the comparison stops at
// the first unequal pair. Floating point NaNs are not considered equal.
//
// It is identical to the standard library's slices.Equal but adds the matching
// nilness check.
func EqualSameNil[S ~[]E, E comparable](s1, s2 S) bool {
	if len(s1) != len(s2) || (s1 == nil) != (s2 == nil) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

// Filter calls fn with each element of the provided src slice, and appends the
// element to dst if fn returns true.
//
// dst can be nil to allocate a new slice, or set to src[:0] to filter in-place
// without allocating.
func Filter[S ~[]T, T any](dst, src S, fn func(T) bool) S {
	for _, x := range src {
		if fn(x) {
			dst = append(dst, x)
		}
	}
	return dst
}

// AppendMatching appends elements in ps to dst if f(x) is true.
func AppendMatching[T any](dst, ps []T, f func(T) bool) []T {
	for _, p := range ps {
		if f(p) {
			dst = append(dst, p)
		}
	}
	return dst
}

// HasPrefix reports whether the byte slice s begins with prefix.
func HasPrefix[E comparable](s, prefix []E) bool {
	return len(s) >= len(prefix) && slices.Equal(s[0:len(prefix)], prefix)
}

// HasSuffix reports whether the slice s ends with suffix.
func HasSuffix[E comparable](s, suffix []E) bool {
	return len(s) >= len(suffix) && slices.Equal(s[len(s)-len(suffix):], suffix)
}

// CutPrefix returns s without the provided leading prefix slice and reports
// whether it found the prefix. If s doesn't start with prefix, CutPrefix
// returns s, false. If prefix is the empty slice, CutPrefix returns s, true.
// CutPrefix returns slices of the original slice s, not copies.
func CutPrefix[E comparable](s, prefix []E) (after []E, found bool) {
	if !HasPrefix(s, prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// CutSuffix returns s without the provided ending suffix slice and reports
// whether it found the suffix. If s doesn't end with suffix, CutSuffix returns
// s, false. If suffix is the empty slice, CutSuffix returns s, true.
// CutSuffix returns slices of the original slice s, not copies.
func CutSuffix[E comparable](s, suffix []E) (after []E, found bool) {
	if !HasSuffix(s, suffix) {
		return s, false
	}
	return s[:len(s)-len(suffix)], true
}

// FirstEqual reports whether len(s) > 0 and
// its first element == v.
func FirstEqual[T comparable](s []T, v T) bool {
	return len(s) > 0 && s[0] == v
}

// LastEqual reports whether len(s) > 0 and
// its last element == v.
func LastEqual[T comparable](s []T, v T) bool {
	return len(s) > 0 && s[len(s)-1] == v
}
