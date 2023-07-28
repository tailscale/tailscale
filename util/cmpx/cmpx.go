// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cmpx has code that will likely land in a future version of Go, but
// we want sooner.
package cmpx

// Or returns the first non-zero element of list, or else returns the zero T.
//
// This is the proposal from
// https://github.com/golang/go/issues/60204#issuecomment-1581245334.
func Or[T comparable](list ...T) T {
	// TODO(bradfitz): remove the comparable constraint so we can use this
	// with funcs too and use reflect to see whether they're non-zero? 🤷‍♂️
	var zero T
	for _, v := range list {
		if v != zero {
			return v
		}
	}
	return zero
}

// Ordered is cmp.Ordered from Go 1.21.
type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64 |
		~string
}

// Compare returns
//
//	-1 if x is less than y,
//	 0 if x equals y,
//	+1 if x is greater than y.
//
// For floating-point types, a NaN is considered less than any non-NaN,
// a NaN is considered equal to a NaN, and -0.0 is equal to 0.0.
func Compare[T Ordered](x, y T) int {
	xNaN := isNaN(x)
	yNaN := isNaN(y)
	if xNaN && yNaN {
		return 0
	}
	if xNaN || x < y {
		return -1
	}
	if yNaN || x > y {
		return +1
	}
	return 0
}

// isNaN reports whether x is a NaN without requiring the math package.
// This will always return false if T is not floating-point.
func isNaN[T Ordered](x T) bool {
	return x != x
}
