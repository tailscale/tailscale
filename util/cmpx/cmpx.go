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
