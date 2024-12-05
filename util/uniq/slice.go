// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package uniq provides removal of adjacent duplicate elements in slices.
// It is similar to the unix command uniq.
package uniq

// ModifySlice removes adjacent duplicate elements from the given slice. It
// adjusts the length of the slice appropriately and zeros the tail.
//
// ModifySlice does O(len(*slice)) operations.
func ModifySlice[E comparable](slice *[]E) {
	// Remove duplicates
	dst := 0
	for i := 1; i < len(*slice); i++ {
		if (*slice)[i] == (*slice)[dst] {
			continue
		}
		dst++
		(*slice)[dst] = (*slice)[i]
	}

	// Zero out the elements we removed at the end of the slice
	end := dst + 1
	var zero E
	for i := end; i < len(*slice); i++ {
		(*slice)[i] = zero
	}

	// Truncate the slice
	if end < len(*slice) {
		*slice = (*slice)[:end]
	}
}

// ModifySliceFunc is the same as ModifySlice except that it allows using a
// custom comparison function.
//
// eq should report whether the two provided elements are equal.
func ModifySliceFunc[E any](slice *[]E, eq func(i, j E) bool) {
	// Remove duplicates
	dst := 0
	for i := 1; i < len(*slice); i++ {
		if eq((*slice)[dst], (*slice)[i]) {
			continue
		}
		dst++
		(*slice)[dst] = (*slice)[i]
	}

	// Zero out the elements we removed at the end of the slice
	end := dst + 1
	var zero E
	for i := end; i < len(*slice); i++ {
		(*slice)[i] = zero
	}

	// Truncate the slice
	if end < len(*slice) {
		*slice = (*slice)[:end]
	}
}
